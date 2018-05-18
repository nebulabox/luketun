#pragma once

#include "tunbase.hpp"
#include "socks5.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_server_session
    : public socks5_session_base,
      public std::enable_shared_from_this<tun_server_session> {
public:
  tun_server_session(asio::io_service &io_context, tcp::socket socket)
      : socks5_session_base(io_context, std::move(socket)) {}

  void start() { handle_request(); }

private:
  void handle_request() {
    auto self(shared_from_this());
    decode_pkg(in_socket_, [this, self](bool succ, tun_pkg &pkg) {
      if (succ) {
        handle_command(pkg.cmd, pkg.body);
      }
    });
  }

  void handle_command(b2 cmd, const bytes &body) {
    // dump_bytes("body", body);
    auto self(shared_from_this());
    if (cmd == GET_URL) { // get the url contents, not impl, only for testing
      string urlstr = string_from_bytes(body);
      log_info("GET URL:", urlstr);
      string s = "<html><head><title>t</title></head><body>body</body></html>";
      in_data_ = encode_pkg(OK, 0, 0, bytes_from_string(s));
      write_to(in_socket_, in_data_, [this, self](bool succ) {});
    } else if (cmd == SOCKS_CONNECT) {
      handle_socks5_request();
    }
  }

  void handle_socks5_request() {
    auto self(shared_from_this());
    read_from(in_socket_, 4, [this, self](bool succ, bytes &data) {
      // CONNECT X'01' BIND X'02' UDP ASSOCIATE X'03'
      b1 VER = data[0]; // 0x05
      b1 CMD = data[1];
      b1 ATYP = data[3];
      if (ATYP == 0x01) {
        // IP V4 address + port
        read_from(in_socket_, 4, [this, self](bool succ, bytes &data) {
          b4 ipv4 = get_b4(data, 0);
          b2 port = get_b2(data, 4);
          remote_host_ = boost::asio::ip::address_v4(ipv4).to_string();
          remote_port_ = std::to_string(port);
          handle_socks5_resolve();
        });
      } else if (ATYP == 0x03) {
        // DOMAINNAME, The first octet contains the number of octets of name
        // that follow, there is no terminating NUL octet.
        read_from(in_socket_, 1, [this, self](bool succ, bytes &data) {
          b1 dnlen = data[0];
          read_from(in_socket_, dnlen + 2,
                    [this, self, dnlen](bool succ, bytes &data) {
                      remote_host_.resize(dnlen);
                      for (int i = 0; i < data.size(); i++) {
                        remote_host_[i] = data[i];
                      }
                      b2 port = get_b2_big_endian(data, dnlen);
                      remote_port_ = std::to_string(port);
                      handle_socks5_resolve();
                    });
        });
      } else if (ATYP == 0x04) {
        log_err("NOT IMPL: Support IPv6 ");
        return;
      } else {
        log_err("Request ATYP wrong value: " + std::to_string(ATYP));
        return;
      }
    });
  }

  void handle_socks5_resolve() {
    auto self(shared_from_this());
    resolve(remote_host_, remote_port_,
            [this, self](bool succ, tcp::resolver::iterator it) {
              if (succ) {
                handle_socks5_connect(it);
              }
            });
  }

  void handle_socks5_connect(const tcp::resolver::results_type::iterator &it) {
    auto self(shared_from_this());
    out_socket_.async_connect(
        *it, [this, self](const boost::system::error_code &ec) {
          if (ec) {
            err("Failed to connect" + remote_host_ + ":" + remote_port_, ec);
            return;
          }
          write_socks5_response();
        });
  }

  void write_socks5_response() {
    auto self(shared_from_this());
    bytes dt = {0x05 /*ver*/, 0x00 /*succ*/, 0x00};
    push_b1(dt, 0x01); // ipv4 type
    // remote ipv4 and port
    b4 realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_uint();
    b2 realRemoteport = out_socket_.remote_endpoint().port();
    push_b4_big_endian(dt, realRemoteIP);
    push_b2_big_endian(dt, realRemoteport);
    write_to(in_socket_, dt, [this, self](bool succ) {
      if (succ) {
        do_read_from_out();
        do_read_from_in();
      }
    });
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    read_from(out_socket_, [this, self](bool succ, bytes &data) {
      if (succ) {
        do_write_to_in(out_data_);
      }
    });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    decode_pkg(in_socket_, [this, self](bool succ, tun_pkg &pkg) {
      if (succ) {
        do_write_to_out(pkg.body);
      }
    });
  }

  void do_write_to_in(bytes &dt) {
    auto self(shared_from_this());
    bytes relaypkg = encode_pkg(SOCKS_CONNECT, 0, 0, dt);
    write_to(in_socket_, relaypkg,
             [this, self](bool succ) { do_read_from_out(); });
  }

  void do_write_to_out(bytes &dt) {
    auto self(shared_from_this());
    write_to(out_socket_, dt, [this, self](bool succ) {
      if (succ) {
        do_read_from_in();
      }
    });
  }

  std::string remote_host_;
  std::string remote_port_;
};

class tun_server {
public:
  tun_server(asio::io_service &io_context, short port)
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
        std::make_shared<tun_server_session>(io_context_, std::move(in_socket_))
            ->start();
      }
      // wait for new connections
      do_accept();
    });
  }
  asio::io_service &io_context_;
  tcp::acceptor acceptor_;
  tcp::socket in_socket_;
};

} // namespace luke
