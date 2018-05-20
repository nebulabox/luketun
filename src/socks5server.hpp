#pragma once

#include "common.hpp"
#include "tunbase.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class socks5_session_base : public tun_session_base {
public:
  ~socks5_session_base() { log_info("Dealloc", "socks5_session_base"); }
  socks5_session_base(asio::io_service &io_context, tcp::socket socket)
      : tun_session_base(io_context, std::move(socket)) {}

  void handle_socks5_negotiation(function<void(bool)> complete) {
    read_from(in_socket_, 2, [&](bool succ, bytes &data) {
      if (!succ)
        return;
      b1 VER = data[0];
      b1 NMETHODS = data[1];
      read_from(in_socket_, NMETHODS, [&](bool succ, bytes &data) {
        if (!succ)
          return;
        // return X'00' NO AUTHENTICATION REQUIRED
        bytes resp = {0x05, 0x00};
        write_to(in_socket_, resp, [&](bool succ) { complete(succ); });
      });
    });
  }

  void handle_socks5_request(
      function<void(bool succ, string host, string port)> complete) {
    std::string hoststr, portstr;
    read_from(in_socket_, 4, [&](bool succ, bytes &data) {
      // CONNECT X'01' BIND X'02' UDP ASSOCIATE X'03'
      b1 VER = data[0]; // 0x05
      b1 CMD = data[1];
      b1 ATYP = data[3];
      if (ATYP == 0x01) {
        // IP V4 address + port
        read_from(in_socket_, 4, [&](bool succ, bytes &data) {
          b4 ipv4 = get_b4(data, 0);
          b2 port = get_b2(data, 4);
          hoststr = boost::asio::ip::address_v4(ipv4).to_string();
          portstr = std::to_string(port);
          complete(true, hoststr, portstr);
        });
      } else if (ATYP == 0x03) {
        // DOMAINNAME, The first octet contains the number of octets of name
        // that follow, there is no terminating NUL octet.
        read_from(in_socket_, 1, [&](bool succ, bytes &data) {
          b1 dnlen = data[0];
          read_from(in_socket_, dnlen + 2, [&](bool succ, bytes &data) {
            hoststr.resize(dnlen);
            for (int i = 0; i < data.size(); i++) {
              hoststr[i] = data[i];
            }
            b2 port = get_b2_big_endian(data, dnlen);
            portstr = std::to_string(port);
            complete(true, hoststr, portstr);
          });
        });
      } else if (ATYP == 0x04) {
        log_err("NOT IMPL: Support IPv6 ");
        return complete(false, hoststr, portstr);
      } else {
        log_err("Request ATYP wrong value: " + std::to_string(ATYP));
        return complete(false, hoststr, portstr);
        ;
      }
    });
  }

  void write_socks5_response(function<void(bool)> complete) {
    bytes dt = {0x05 /*ver*/, 0x00 /*succ*/, 0x00};
    push_b1(dt, 0x01); // ipv4 type
                       // remote ipv4 and port
    b4 realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_uint();
    b2 realRemoteport = out_socket_.remote_endpoint().port();
    push_b4_big_endian(dt, realRemoteIP);
    push_b2_big_endian(dt, realRemoteport);
    write_to(in_socket_, dt, [&](bool succ) { complete(succ); });
  }
};

class socks5_server_session
    : public socks5_session_base,
      public std::enable_shared_from_this<socks5_server_session> {
public:
  ~socks5_server_session() { log_info("Dealloc", "socks5_server_session"); }
  socks5_server_session(asio::io_service &io_context, tcp::socket socket)
      : socks5_session_base(io_context, std::move(socket)) {}

  void start(function<void(void)> session_finished) {
    auto self(shared_from_this());
    handle_socks5_negotiation([this, self](bool succ) {
      if (!succ)
        return;
      handle_socks5_request([this, self](bool succ, string host, string port) {
        if (!succ)
          return;
        resolve_addr(
            host, port,
            [this, self](bool succ, tcp::resolver::iterator addr_iterator) {
              if (!succ)
                return;
              connect_to(out_socket_, addr_iterator, [this, self](bool succ) {
                if (!succ)
                  return;
                write_socks5_response([this, self](bool succ) {
                  if (!succ)
                    return;
                  do_read_from_out();
                  do_read_from_in();
                });
              });
            });
      });
    });
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    read_from(out_socket_, [this, self](bool succ, bytes &data) {
      if (!succ)
        return;
      do_write_to_in(data);
    });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    read_from(in_socket_, [this, self](bool succ, bytes &data) {
      if (!succ)
        return;
      do_write_to_out(data);
    });
  }

  void do_write_to_in(bytes &dt) {
    auto self(shared_from_this());
    write_to(in_socket_, dt, [this, self](bool succ) {
      if (!succ)
        return;
      do_read_from_in();
    });
  }

  void do_write_to_out(bytes &dt) {
    auto self(shared_from_this());
    write_to(out_socket_, dt, [this, self](bool succ) {
      if (!succ)
        return;
      do_read_from_in();
    });
  }
}; // namespace luke

class socks5_server {
public:
  ~socks5_server() { log_info("Dealloc", "socks5_server"); }
  socks5_server(asio::io_service &io_context, short port)
      : io_context_(io_context),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
        in_socket_(io_context) {
    do_accept();
  }

private:
  void do_accept() {
    acceptor_.async_accept(in_socket_, [this](std::error_code ec) {
      if (!ec) {
        // start a new session to do works
        auto sess = std::make_shared<socks5_server_session>(
            io_context_, std::move(in_socket_));
        sessions_lock.lock();
        sessions.insert(sess);
        sessions_lock.unlock();
        sess->start([&]() {
          // session finished
          sessions_lock.lock();
          sessions.erase(sess);
          sessions_lock.unlock();
        });
      }
      // wait for new connections
      do_accept();
    });
  }
  asio::io_service &io_context_;
  tcp::acceptor acceptor_;
  tcp::socket in_socket_;

  std::mutex sessions_lock;
  std::unordered_set<std::shared_ptr<socks5_server_session>> sessions;
};

} // namespace luke
