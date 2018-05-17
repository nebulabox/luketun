#pragma once

#include "common.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_server_session
    : public std::enable_shared_from_this<tun_server_session> {
public:
  tun_server_session(asio::io_context &io_context, tcp::socket socket)
      : io_context_(io_context), in_socket_(std::move(socket)),
        out_socket_(io_context), resolver(io_context) {}

  void start() { handle_request(); }

private:
  void handle_request() { auto self(shared_from_this());
   }

  void handle_response() { auto self(shared_from_this()); }

  asio::io_context &io_context_;
  tcp::socket in_socket_;
  tcp::socket out_socket_;
  tcp::resolver resolver;
  bytes in_data_;
  bytes out_data_;
  string remote_host_;
  string remote_port_;
  const int MAX_BUF_SIZE = 65535;
}; // namespace luke

class tun_server {
public:
  tun_server(asio::io_context &io_context, short port)
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
  asio::io_context &io_context_;
  tcp::acceptor acceptor_;
  tcp::socket in_socket_;
};

} // namespace luke
