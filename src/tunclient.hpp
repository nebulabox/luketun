#pragma once

#include "tunbase.hpp"
#include "socks5.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_client_session
    : public socks5_session_base,
      public std::enable_shared_from_this<tun_client_session> {
public:
  tun_client_session(asio::io_service &io_context, tcp::socket socket)
      : socks5_session_base(io_context, std::move(socket)) {}

  void start() {
    auto self(shared_from_this());
    tunserver_host_ = "127.0.0.1";
    tunserver_port_ = "2484";
    resolver.async_resolve(
        tcp::resolver::query(tunserver_host_, tunserver_port_),
        [this, self](const boost::system::error_code &ec,
                     tcp::resolver::iterator it) {
          out_socket_.async_connect(
              *it, [this, self](const boost::system::error_code &ec) {
                if (ec) {
                  log_err("Failed to connect tun server" + tunserver_host_ +
                              ":" + tunserver_port_,
                          ec);
                  return;
                }
                // log_info("Connected to ", remote_host_ + ":" + remote_port_);
                // test get url
                // bytes data = bytes_from_string("https://www.baidu.com");
                // bytes req = encode_pkg(GET_URL, 0, 0, data);
                // boost::asio::async_write(
                //     out_socket_, boost::asio::buffer(req, req.size()),
                //     [this, self](boost::system::error_code ec,
                //                  std::size_t length) {
                //       if (ec) {
                //         log_err("Write to out", ec);
                //         in_socket_.close();
                //         out_socket_.close();
                //         return;
                //       }
                //       do_read_from_out();
                //     });

                // start from socks5 session negotiation
                handle_socks5_negotiation();
              });
        });
  }

private:
  void handle_socks5_negotiation() {
    auto self(shared_from_this());
    read_from(in_socket_, 2, [this, self](bool succ, bytes &data) {
      if (!succ)
        return;
      b1 VER = data[0];
      b1 NMETHODS = data[1];
      read_from(in_socket_, NMETHODS, [this, self](bool succ, bytes &data) {
        if (!succ)
          return;
        // return X'00' NO AUTHENTICATION REQUIRED
        bytes resp = {0x05, 0x00};
        write_to(in_socket_, resp, [this, self](bool succ) {
          if (!succ)
            return;
          do_read_from_out();
          do_read_from_in();
        });
      });
    });
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    decode_pkg(out_socket_, [this, self](bool succ, tun_pkg &pkg) {
      if (succ) {
        do_write_to_in(pkg.body);
      }
    });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    read_from(in_socket_, [this, self](bool succ, bytes &data) {
      if (succ) {
        do_write_to_out(data);
      }
    });
  }

  void do_write_to_in(bytes &dt) {
    auto self(shared_from_this());
    write_to(in_socket_, dt, [this, self](bool succ) {
      if (succ) {
        do_read_from_out();
      }
    });
  }

  void do_write_to_out(bytes &dt) {
    auto self(shared_from_this());
    bytes relaypkg = encode_pkg(SOCKS_CONNECT, 0, 0, dt);
    write_to(out_socket_, relaypkg, [this, self](bool succ) {
      if (succ) {
        do_read_from_in();
      }
    });
  }

  string tunserver_host_;
  string tunserver_port_;
};

class tun_client {
public:
  tun_client(asio::io_service &io_context, short port)
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
        std::make_shared<tun_client_session>(io_context_, std::move(in_socket_))
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
