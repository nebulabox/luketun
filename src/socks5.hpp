#pragma once

#include "common.hpp"
#include "tunbase.hpp"

namespace luke {

using namespace boost;
using namespace boost::asio::ip;
using namespace std;

class socks5_session_base : public tun_session_base {
public:
  socks5_session_base(asio::io_service &io_context, tcp::socket socket)
      : tun_session_base(io_context, std::move(socket)) {}
};

class socks5_server_session
    : public socks5_session_base,
      public std::enable_shared_from_this<socks5_server_session> {
public:
  socks5_server_session(asio::io_service &io_context, tcp::socket socket)
      : socks5_session_base(io_context, std::move(socket)) {}

  void start() { handle_negotiation(); }

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
                            handle_request();
                          });
                    });
              });
        });
  }

  void handle_request() {
    auto self(shared_from_this());
    in_data_.resize(4);
    asio::async_read(
        in_socket_, asio::buffer(in_data_, 4),
        [this, self](std::error_code ec, std::size_t length) {
          if (ec || length != 4) {
            log_err("Read requst first 4 bytes", ec);
            return;
          }
          if (this->in_data_[0] != 0x05) {
            log_err("Request VER", ec);
            return;
          }
          // CONNECT X'01' BIND X'02' UDP ASSOCIATE X'03'
          b1 CMD = this->in_data_[1];
          b1 ATYP = this->in_data_[3];
          if (ATYP == 0x01) {
            // IP V4 address + port
            in_data_.resize(6);
            asio::async_read(
                in_socket_, asio::buffer(in_data_, 6),
                [this, self](std::error_code ec, std::size_t length) {
                  if (ec || length != 6) {
                    log_err("Read IPv4 and port", ec);
                    return;
                  }
                  b4 ipv4 = get_b4(in_data_, 0);
                  b2 port = get_b2(in_data_, 4);
                  remote_host_ = boost::asio::ip::address_v4(ipv4).to_string();
                  remote_port_ = std::to_string(port);
                  handle_resolve();
                });
          } else if (ATYP == 0x03) {
            // DOMAINNAME, The first octet contains the number of octets of name
            // that follow, there is no terminating NUL octet.
            in_data_.resize(1);
            asio::async_read(
                in_socket_, asio::buffer(in_data_, 1),
                [this, self](std::error_code ec, std::size_t length) {
                  if (ec || length != 1) {
                    log_err("Read domain name length", ec);
                    return;
                  }
                  b1 dnlen = this->in_data_[0];
                  in_data_.resize(dnlen + 2);
                  asio::async_read(
                      in_socket_, asio::buffer(in_data_, dnlen + 2),
                      [this, self, dnlen](std::error_code ec,
                                          std::size_t length) {
                        if (ec || length != dnlen + 2) {
                          log_err("Read domain name", ec);
                          return;
                        }
                        remote_host_.resize(dnlen);
                        for (int i = 0; i < in_data_.size(); i++) {
                          remote_host_[i] = in_data_[i];
                        }
                        b2 port = get_b2_big_endian(in_data_, dnlen);
                        remote_port_ = std::to_string(port);
                        // log_info("remote_host_", remote_host_);
                        // log_info("remote_host_", remote_port_);
                        handle_resolve();
                      });
                });
          } else if (ATYP == 0x04) {
            log_err("TODO: Support IPv6 ");
            return;
          } else {
            log_err("Request ATYP wrong value: " + std::to_string(ATYP));
            return;
          }
        });
  }

  void handle_resolve() {
    auto self(shared_from_this());
    resolver.async_resolve(tcp::resolver::query(remote_host_, remote_port_),
                           [this, self](const boost::system::error_code &ec,
                                        tcp::resolver::iterator it) {
                             if (ec) {
                               log_err("Resolve", ec);
                               return;
                             }
                             handle_connect(it);
                           });
  }

  void handle_connect(const tcp::resolver::results_type::iterator &it) {
    auto self(shared_from_this());
    out_socket_.async_connect(*it, [this,
                                    self](const boost::system::error_code &ec) {
      if (ec) {
        log_err("Failed to connect" + remote_host_ + ":" + remote_port_, ec);
        return;
      }
      // log_info("Connected to ", remote_host_ + ":" + remote_port_);
      write_socks5_response();
    });
  }

  void write_socks5_response() {
    auto self(shared_from_this());
    in_data_ = {0x05 /*ver*/, 0x00 /*succ*/, 0x00};
    push_b1(in_data_, 0x01); // ipv4 type
    // remote ipv4 and port
    b4 realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_uint();
    b2 realRemoteport = out_socket_.remote_endpoint().port();
    push_b4_big_endian(in_data_, realRemoteIP);
    push_b2_big_endian(in_data_, realRemoteport);
    boost::asio::async_write(
        in_socket_, boost::asio::buffer(in_data_, in_data_.size()),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("Write socks5 resp", ec);
            return;
          }
          do_read_from_out();
          do_read_from_in();
        });
  }

  void do_read_from_out() {
    auto self(shared_from_this());
    out_data_.resize(MAX_BUF_SIZE);
    out_socket_.async_receive(
        boost::asio::buffer(out_data_, MAX_BUF_SIZE),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("read from out", ec);
            in_socket_.close();
            out_socket_.close();
            return;
          }
          // dump_bytes("do_read_from_out", out_data_);
          do_write_to_in(out_data_, length);
        });
  }

  void do_read_from_in() {
    auto self(shared_from_this());
    in_data_.resize(MAX_BUF_SIZE);
    in_socket_.async_receive(
        boost::asio::buffer(in_data_, MAX_BUF_SIZE),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            log_err("read from in", ec);
            in_socket_.close();
            out_socket_.close();
            return;
          }
          // dump_bytes("do_read_from_in", in_data_);
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
    boost::asio::async_write(
        out_socket_, boost::asio::buffer(dt, length),
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

  // asio::io_service &io_context_;
  // tcp::socket in_socket_;
  // tcp::socket out_socket_;
  // tcp::resolver resolver;
  // bytes in_data_;
  // bytes out_data_;
  string remote_host_;
  string remote_port_;
}; // namespace luke

class socks5_server {
public:
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
        std::make_shared<socks5_server_session>(io_context_,
                                                std::move(in_socket_))
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
