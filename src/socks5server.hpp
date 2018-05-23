#pragma once

#include "common.hpp"
#include "tunbase.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class socks5_server_session : public tun_session_base,
                              public std::enable_shared_from_this<socks5_server_session> {
 public:
  ~socks5_server_session() { log_info("Dealloc", "socks5_server_session"); }
  socks5_server_session(asio::io_service &io_context, tcp::socket socket)
      : tun_session_base(io_context), in_socket_(std::move(socket)), out_socket_(io_context) {}

  void start() {
    auto self(shared_from_this());
    handle_socks5_negotiation(in_socket_, [this, self] {
      handle_socks5_request(in_socket_, [this, self](string host, string port) {
        connect_to(out_socket_, host, port, [this, self] {
          write_socks5_response(in_socket_, out_socket_, [this, self]() {
            do_read_from_out();
            do_read_from_in();
          });
        });
      });
    });
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    read_from(out_socket_, [this, self](bytes &data) { do_write_to_in(data); });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    read_from(in_socket_, [this, self](bytes &data) { do_write_to_out(data); });
  }

  void do_write_to_in(bytes &dt) {
    auto self(shared_from_this());
    write_to(in_socket_, dt, [this, self] { do_read_from_out(); });
  }

  void do_write_to_out(bytes &dt) {
    auto self(shared_from_this());
    write_to(out_socket_, dt, [this, self] { do_read_from_in(); });
  }

  tcp::socket in_socket_;
  tcp::socket out_socket_;
};

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
      if (ec) {
        log_err("do_accept", ec);
        return do_accept();
      }
      // start a new session to do works
      std::make_shared<socks5_server_session>(io_context_, std::move(in_socket_))->start();
      // wait for new connections
      do_accept();
    });
  }

  asio::io_service &io_context_;
  tcp::acceptor acceptor_;
  tcp::socket in_socket_;
};

}  // namespace luke
