#pragma once

#include "socks5server.hpp"
#include "tunbase.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_server_session
    : public tun_session_base,
      public std::enable_shared_from_this<tun_server_session> {
public:
  tun_server_session(asio::io_service &io_context, tcp::socket socket)
      : tun_session_base(io_context, std::move(socket)) {}

  void start() { handle_request(); }

private:
  void handle_request() {
    auto self(shared_from_this());
    decode_pkg(in_socket_, [this, self](tun_pkg pkg) {
      handle_command(pkg.cmd, pkg.body);
    });
  }

  void handle_command(b2 cmd, const bytes &body) {
    // dump_bytes("body", body);
    auto self(shared_from_this());
    if (cmd == GET_URL) { // get the url contents, not impl, only for testing
      string urlstr = string_from_bytes(body);
      log_info("GET URL:", urlstr);
      string s = "<html><head><title>t</title></head><body>body</body></html>";
      bytes data = encode_pkg(OK, 0, 0, bytes_from_string(s));
      write_to(in_socket_, data, [this, self]() {});
    } else if (cmd == SOCKS_CONNECT) {
      handle_socks5_request([this, self](string host, string port) {
        connect_to(out_socket_, host, port, [this, self]() {
          write_socks5_response([this, self]() {
            do_read_from_out();
            do_read_from_in();
          });
        });
      });
    }
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    read_from(out_socket_, [this, self](bytes &data) { do_write_to_in(data); });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    decode_pkg(in_socket_,
               [this, self](tun_pkg pkg) { do_write_to_out(pkg.body); });
  }

  void do_write_to_in(bytes &dt) {
    auto self(shared_from_this());
    bytes relaypkg = encode_pkg(SOCKS_CONNECT, 0, 0, dt);
    write_to(in_socket_, relaypkg, [this, self]() { do_read_from_out(); });
  }

  void do_write_to_out(bytes &dt) {
    auto self(shared_from_this());
    write_to(out_socket_, dt, [this, self]() { do_read_from_in(); });
  }
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
