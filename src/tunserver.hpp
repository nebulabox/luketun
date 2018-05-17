#pragma once

#include "common.hpp"
#include "crypto.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_server_session
    : public std::enable_shared_from_this<tun_server_session> {
public:
  tun_server_session(asio::io_context &io_context, tcp::socket socket)
      : io_context_(io_context), in_socket_(std::move(socket)),
        out_socket_(io_context), resolver(io_context), crp("@@abort();") {}

  void start() { handle_request(); }

private:
  /* request
  crypto header length: 2 bytes
  crypto header data
    client ver b4: 20180517
    cmd b4
    crypto body data len b4
  crypto real body data
  */
  void handle_request() {
    auto self(shared_from_this());
    in_data_.resize(2);
    asio::async_read(
        in_socket_, asio::buffer(in_data_, 2),
        [this, self](std::error_code ec, std::size_t length) {
          if (ec || length != 2) {
            log_err("Read header len", ec);
            return;
          }
          b2 header_len = get_b2(in_data_, 0);
          in_data_.resize(header_len);
          asio::async_read(
              in_socket_, asio::buffer(in_data_, header_len),
              [this, self, header_len](std::error_code ec, std::size_t length) {
                if (ec || length != header_len) {
                  log_err("Read header data", ec);
                  return;
                }
                // decrpyt header
                bytes header = crp.decrypt(in_data_);
                int pos = 0;
                b4 ver = get_b4(header, pos);
                pos += 4;
                b2 cmd = get_b4(header, pos);
                pos += 4;
                b4 body_len = get_b4(header, pos);
                pos += 4;
                in_data_.resize(body_len);
                asio::async_read(in_socket_, asio::buffer(in_data_, body_len),
                                 [this, self, body_len,
                                  cmd](std::error_code ec, std::size_t length) {
                                   if (ec || length != body_len) {
                                     log_err("Read body data", ec);
                                     return;
                                   }
                                   // decrpyt body
                                   bytes body = crp.decrypt(in_data_);
                                   handle_command(cmd, body);
                                 });
              });
        });
  }

  void handle_command(b2 cmd, const bytes &body) {
    // dump_bytes("body", body);
    auto self(shared_from_this());
    if (cmd == GET_URL) {
      // get the url contents, not impl, only for testing
      string urlstr = string_from_bytes(body);
      log_info("GET URL:", urlstr);
      string content = R"(
<!doctype html>
<html lang=en>
  <head>
    <meta charset=utf-8>
  <title>test result</title>
  </head>
  <body>
    <p>I'm the content</p>
  </body>
</html>
)";
    in_data_ = make_response(OK, bytes_from_string(content));
    boost::asio::async_write(
        in_socket_, boost::asio::buffer(in_data_, in_data_.size()),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("Write resp", ec);
            return;
          }
        });
    } else if (cmd == SOCKS_CONNECT) {
      // todo
      // handle_response();
    }
  }

  /* response
  crypto header length: 2 bytes
  crypto header data
    server ver b4: 20180517
    cmd result b4
    crypto body data len b4
  crypto real body data
  */
  const bytes make_response(b4 cmd_result, const bytes &body_data) {
    bytes ret;
    bytes encrpyt_body = crp.encrypt(body_data);
    bytes header_data;
    push_b4(header_data, VER);
    push_b4(header_data, cmd_result);
    push_b4(header_data, encrpyt_body.size()); // crypto body size
    bytes encrpyt_header = crp.encrypt(header_data);
    push_b2(ret, encrpyt_header.size()); // header length
    push_bytes(ret, encrpyt_header);
    push_bytes(ret, encrpyt_body);
    return ret;
  }

  asio::io_context &io_context_;
  tcp::socket in_socket_;
  tcp::socket out_socket_;
  tcp::resolver resolver;
  bytes in_data_;
  bytes out_data_;
  luke::crypto crp;
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
