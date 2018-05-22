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
      : tun_session_base(io_context, std::move(socket)) {}

  void start(function<void(void)> exit_handler) {
    session_exit_handler = exit_handler;
    handle_socks5_negotiation([this]() {
      handle_socks5_request([this](string host, string port) {
        connect_to(out_socket_, host, port, [this]() {
          write_socks5_response([this]() {
            do_read_from_out();
            do_read_from_in();
          });
        });
      });
    });
  }

  void do_read_from_out() {
    read_from(out_socket_, [this](bytes &data) { do_write_to_in(data); });
  }

  void do_read_from_in() {
    read_from(in_socket_, [this](bytes &data) { do_write_to_out(data); });
  }

  void do_write_to_in(bytes &dt) {
    write_to(in_socket_, dt, [this]() { do_read_from_out(); });
  }

  void do_write_to_out(bytes &dt) {
    write_to(out_socket_, dt, [this]() { do_read_from_in(); });
  }
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
      auto sess = std::make_shared<socks5_server_session>(io_context_, std::move(in_socket_));
      sessions_lock.lock();
      sessions.insert(sess);
      sessions_lock.unlock();
      log_info("===>> Create session, after count=", to_string(sessions.size()));
      sess->start([this, weaksess = std::weak_ptr<socks5_server_session>(sess)]() {
        if (auto sess = weaksess.lock()) {
          // session exit
          sessions_lock.lock();
          if (sessions.find(sess) != sessions.end()) {
            sessions.erase(sess);
          }
          sessions_lock.unlock();
          log_info("===>> Exit session, after count=", to_string(sessions.size()));
        }
      });
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

}  // namespace luke
