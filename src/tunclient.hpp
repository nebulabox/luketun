#pragma once

#include "socks5server.hpp"
#include "tunbase.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_client_session : public tun_session_base,
                           public std::enable_shared_from_this<tun_client_session> {
 public:
  tun_client_session(asio::io_service &io_context, tcp::socket socket)
      : tun_session_base(io_context) {}

  void start() {
    //    auto self(shared_from_this());
    //    tunserver_host_ = "127.0.0.1";
    //    tunserver_port_ = "2484";
    //    resolver_.async_resolve(
    //        tcp::resolver::query(tunserver_host_, tunserver_port_),
    //        [this, self](const boost::system::error_code &ec,
    //                     tcp::resolver::iterator it) {
    //          out_socket_.async_connect(
    //              *it, [this, self](const boost::system::error_code &ec) {
    //                if (ec) {
    //                  log_err("Failed to connect tun server" + tunserver_host_ +
    //                              ":" + tunserver_port_,
    //                          ec);
    //                  return;
    //                }
    //
    //                // start from socks5 session negotiation
    //                handle_socks5_negotiation([this, self]() {
    //                        do_read_from_out();
    //                        do_read_from_in();
    //                });
    //              });
    //        });
  }

 private:
  //  void do_read_from_out() {
  //    auto self(shared_from_this());
  //    decode_pkg(out_socket_, [this, self](tun_pkg pkg) {
  //        do_write_to_in(pkg.body);
  //    });
  //  }
  //
  //  void do_read_from_in() {
  //    auto self(shared_from_this());
  //    read_from(in_socket_, [this, self](bytes &data) {
  //        do_write_to_out(data);
  //    });
  //  }
  //
  //  void do_write_to_in(bytes &dt) {
  //    auto self(shared_from_this());
  //    write_to(in_socket_, dt, [this, self]() {
  //        do_read_from_out();
  //    });
  //  }
  //
  //  void do_write_to_out(bytes &dt) {
  //    auto self(shared_from_this());
  //    bytes relaypkg = encode_pkg(SOCKS_CONNECT, 0, 0, dt);
  //    write_to(out_socket_, relaypkg, [this, self]() {
  //        do_read_from_in();
  //    });
  //  }

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
        std::make_shared<tun_client_session>(io_context_, std::move(in_socket_))->start();
      }
      // wait for new connections
      do_accept();
    });
  }
  asio::io_service &io_context_;
  tcp::acceptor acceptor_;
  tcp::socket in_socket_;
};

}  // namespace luke
