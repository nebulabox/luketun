#pragma once

#include "common.hpp"
#include "crypto.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class tun_client_session
    : public std::enable_shared_from_this<tun_client_session> {
public:
  tun_client_session(asio::io_context &io_context, tcp::socket socket)
      : io_context_(io_context), in_socket_(std::move(socket)),
        out_socket_(io_context), resolver(io_context), crp("@@abort();") {}

  void start() {
    auto self(shared_from_this());
    tunserver_host_ = "127.0.0.1";
    tunserver_port_ = "2484";
    resolver.async_resolve(
        tunserver_host_, tunserver_port_,
        [this, self](const boost::system::error_code &ec,
                     asio::ip::tcp::resolver::results_type results) {
          if (ec || results.size() <= 0) {
            log_err("Failed to resolve tun server host", ec);
            return;
          }
          out_socket_.async_connect(
              *(results.begin()),
              [this, self](const boost::system::error_code &ec) {
                if (ec) {
                  log_err("Failed to connect tun server" + tunserver_host_ +
                              ":" + tunserver_port_,
                          ec);
                  return;
                }
                // log_info("Connected to ", remote_host_ + ":" + remote_port_);
                // test get url
                bytes data = bytes_from_string("https://www.baidu.com");
                bytes req = make_request(GET_URL, data);
                boost::asio::async_write(
                    out_socket_, boost::asio::buffer(req, req.size()),
                    [this, self](boost::system::error_code ec,
                                 std::size_t length) {
                      if (ec) {
                        log_err("Write to out", ec);
                        in_socket_.close();
                        out_socket_.close();
                        return;
                      }
                      do_read_from_out();
                    });

                // start from socks5 session negotiation
                // handle_negotiation();
              });
        });
  }

private:
  void handle_negotiation() {
    auto self(shared_from_this());

    in_data_.resize(1);
    asio::async_read(
        in_socket_, asio::buffer(in_data_, 1),
        [this, self](std::error_code ec, std::size_t length) {
          if (ec || length != 1) {
            log_err("Read VER", ec);
            return;
          }
          b1 VER = this->in_data_[0];
          // out << "Client Use Socks VER: " << VER << endl;

          in_data_.resize(1);
          asio::async_read(
              this->in_socket_, asio::buffer(this->in_data_, 1),
              [this, self](std::error_code ec, std::size_t length) {
                if (ec || length != 1) {
                  log_err("read NMETHODS", ec);
                  return;
                }
                b1 NMETHODS = this->in_data_[0];
                // cout << "NMETHODS: " << NMETHODS << endl;

                in_data_.resize(NMETHODS);
                asio::async_read(
                    this->in_socket_, asio::buffer(this->in_data_, NMETHODS),
                    [this, self, NMETHODS](std::error_code ec,
                                           std::size_t length) {
                      if (ec || length != NMETHODS) {
                        log_err("read METHODS", ec);
                        return;
                      }
                      // dump_bytes("METHODS", in_data_);
                      // return X'00' NO AUTHENTICATION REQUIRED
                      this->in_data_ = {0x05, 0x00};
                      asio::async_write(
                          this->in_socket_,
                          asio::buffer(this->in_data_, this->in_data_.size()),
                          [this, self](std::error_code ec, std::size_t length) {
                            if (ec) {
                              log_err("return negotiation", ec);
                              return;
                            }
                            // relay start
                            // socks5 client <->[in]tunclient[out]<->
                            // [in]tunserver[out] <-> real site
                            do_read_from_out();
                            do_read_from_in();
                          });
                    });
              });
        });
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    out_data_.resize(2);
    asio::async_read(
        out_socket_, asio::buffer(out_data_, 2),
        [this, self](std::error_code ec, std::size_t length) {
          if (ec || length != 2) {
            log_err("[out]Read header len", ec);
            return;
          }
          b2 header_len = get_b2(out_data_, 0);
          out_data_.resize(header_len);
          asio::async_read(
              out_socket_, asio::buffer(out_data_, header_len),
              [this, self, header_len](std::error_code ec, std::size_t length) {
                if (ec || length != header_len) {
                  log_err("[out]Read header data", ec);
                  return;
                }
                // decrpyt header
                bytes header = crp.decrypt(out_data_);
                int pos = 0;
                b4 ver = get_b4(header, pos);
                pos += 4;
                b2 cmd = get_b4(header, pos);
                pos += 4;
                b4 body_len = get_b4(header, pos);
                pos += 4;
                out_data_.resize(body_len);
                asio::async_read(out_socket_, asio::buffer(out_data_, body_len),
                                 [this, self, body_len](std::error_code ec,
                                                        std::size_t length) {
                                   if (ec || length != body_len) {
                                     log_err("[out]Read body data", ec);
                                     return;
                                   }
                                   // decrpyt body
                                   bytes body = crp.decrypt(out_data_);
                                   //  dump_bytes("[out]body", body);
                                   // cout << string_from_bytes(body);
                                   // now we have body from out, send it to in
                                   do_write_to_in(body, body.size());
                                 });
              });
        });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    in_data_.resize(MAX_BUF_SIZE);
    in_socket_.async_receive(
        boost::asio::buffer(in_data_, MAX_BUF_SIZE),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("Read from in", ec);
            in_socket_.close();
            out_socket_.close();
            return;
          }
          // dump_bytes("do_read_from_in", in_data_);
          // we got data from in, relay it to out
          do_write_to_out(in_data_, length);
        });
  }

  void do_write_to_in(bytes &dt, std::size_t length) {
    auto self(shared_from_this());
    boost::asio::async_write(
        in_socket_, boost::asio::buffer(dt, length),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("Write to in", ec);
            in_socket_.close();
            out_socket_.close();
            return;
          }
          do_read_from_out();
        });
  }

  void do_write_to_out(bytes &dt, std::size_t length) {
    auto self(shared_from_this());
    bytes relaypkg = make_request(SOCKS_CONNECT, dt);
    boost::asio::async_write(
        out_socket_, boost::asio::buffer(relaypkg, relaypkg.size()),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("Write to out", ec);
            in_socket_.close();
            out_socket_.close();
            return;
          }
          do_read_from_in();
        });
  }

  /* request
  crypto header length: 2 bytes
  crypto header data
    client ver b4: 20180517
    cmd b4
    crypto body data len b4
  crypto real body data
  */
  const bytes make_request(b4 cmd, const bytes &body_data) {
    bytes ret;
    bytes encrpyt_body = crp.encrypt(body_data);
    bytes header_data;
    push_b4(header_data, VER);
    push_b4(header_data, cmd);
    push_b4(header_data, (b4)encrpyt_body.size()); // crypto body size
    bytes encrpyt_header = crp.encrypt(header_data);
    push_b2(ret, (b2)encrpyt_header.size()); // header length
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
  string tunserver_host_;
  string tunserver_port_;
  luke::crypto crp;
}; // namespace luke

class tun_client {
public:
  tun_client(asio::io_context &io_context, short port)
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
  asio::io_context &io_context_;
  tcp::acceptor acceptor_;
  tcp::socket in_socket_;
};

} // namespace luke
