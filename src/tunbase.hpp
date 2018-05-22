#pragma once
#include "common.hpp"
#include "crypto.hpp"

namespace luke {
using namespace boost;
using namespace boost::asio::ip;
using namespace std;

/* request or response wrapper pkg
crypto header length: 2 bytes
crypto header data
  server ver b4: 20180517
  cmd result b4
  id b4
  flags b4
  crypto body data len b4
crypto real body data
*/
struct tun_pkg {
  b4 ver;
  b4 cmd;
  b4 id;
  b4 flags;
  bytes body;
};

class tun_session_base {
 public:
  ~tun_session_base() {
    // log_info("Dealloc", "tun_session_base");
  }
  tun_session_base(asio::io_service& io_context, tcp::socket socket)
      : io_context_(io_context),
        in_socket_(std::move(socket)),
        out_socket_(io_context),
        resolver_(io_context),
        crp_("@@abort();") {}

  const bytes encode_pkg(b4 cmd_or_result, b4 id, b4 flags, const bytes& body_data) {
    bytes ret;
    bytes encrpyt_body;
    crp_.encrypt(body_data, encrpyt_body);
    bytes header_data;
    push_b4(header_data, VER);
    push_b4(header_data, cmd_or_result);
    push_b4(header_data, id);
    push_b4(header_data, flags);
    push_b4(header_data, (b4)encrpyt_body.size());  // crypto body size
    bytes encrpyt_header;
    crp_.encrypt(header_data, encrpyt_header);
    push_b2(ret, (b2)encrpyt_header.size());  // header length
    push_bytes(ret, encrpyt_header);
    push_bytes(ret, encrpyt_body);
    return ret;
  }

  void close_sockets() {
    try {
      in_socket_.close();
    } catch (...) {
    }
    try {
      out_socket_.close();
    } catch (...) {
    }
    try {
      resolver_.cancel();
    } catch (...) {
    }
  }

  void err(const std::string msg, const std::error_code ec) {
    close_sockets();
    if (session_exit_handler) session_exit_handler();
    session_exit_handler = nullptr;
    // log_info(msg, ec);
  }

  void err(const std::string msg) {
    std::error_code ec;
    err(msg, ec);
  }

  void decode_pkg(tcp::socket& sk, function<void(tun_pkg pkg)> handler) {
    asio::async_read(
        sk, asio::buffer(dt_, 2), [this, &sk, handler](std::error_code ec, std::size_t length) {
          if (ec || length != 2) return err("Read header len", ec);
          b2 header_len = get_b2(dt_, 0);
          dt_.resize(header_len);
          asio::async_read(
              sk, asio::buffer(dt_, header_len),
              [this, &sk, handler, header_len](std::error_code ec, std::size_t length) {
                if (ec || length != header_len) return err("Read header data", ec);
                // decrpyt header
                tun_pkg pkg;
                bytes header;
                crp_.decrypt(dt_, header);
                int pos = 0;
                pkg.ver = get_b4(header, pos);
                pos += 4;
                pkg.cmd = get_b4(header, pos);
                pos += 4;
                pkg.id = get_b4(header, pos);
                pos += 4;
                pkg.flags = get_b4(header, pos);
                pos += 4;
                b4 body_len = get_b4(header, pos);
                pos += 4;
                dt_.resize(body_len);
                asio::async_read(
                    sk, asio::buffer(dt_, body_len),
                    [this, &sk, handler, pkg, body_len](std::error_code ec, std::size_t length) {
                      if (ec || length != body_len) return err("Read body data", ec);
                      // decrpyt body
                      tun_pkg outpkg = pkg;
                      crp_.decrypt(dt_, outpkg.body);
                      //  dump_bytes("[out]body", body);
                      // cout << string_from_bytes(body);
                      if (handler) handler(outpkg);
                    });
              });
        });
  }

  void write_to(tcp::socket& sk, bytes& bs, function<void(void)> handler) {
    boost::asio::async_write(sk, boost::asio::buffer(bs, bs.size()),
                             [this, handler](boost::system::error_code ec, std::size_t length) {
                               if (ec) return err("Write to", ec);
                               if (handler) handler();
                             });
  }

  void read_from(tcp::socket& sk, function<void(bytes& data)> handler) {
    dt_.resize(MAX_BUF_SIZE);
    sk.async_receive(boost::asio::buffer(dt_, MAX_BUF_SIZE),
                     [this, handler](boost::system::error_code ec, std::size_t length) {
                       if (ec) return err("read from", ec);
                       dt_.resize(length);
                       if (handler) handler(dt_);
                     });
  }

  void read_from(tcp::socket& sk, size_t count, function<void(bytes& data)> handler) {
    // read certain numbers
    dt_.resize(count);
    asio::async_read(sk, boost::asio::buffer(dt_, count),
                     [this, handler, count](boost::system::error_code ec, std::size_t length) {
                       if (ec) return err("read from", ec);
                       if (length != count) return err("read from length != count", ec);
                       if (handler) handler(dt_);
                     });
  }

  void connect_to(tcp::socket& sk, string host, string port, function<void(void)> complete) {
    resolver_.async_resolve(
        tcp::resolver::query(host, port),
        [this, &sk, complete](const boost::system::error_code& ec, tcp::resolver::iterator it) {
          if (ec) return err("Resolve", ec);
          sk.async_connect(*it, [this, complete](const boost::system::error_code& ec) {
            if (ec) return err("Failed to connect", ec);
            if (complete) complete();
          });
        });
  }

  void handle_socks5_negotiation(function<void(void)> complete) {
    read_from(in_socket_, 2, [this, complete](bytes& data) {
      b1 VER = data[0];
      b1 NMETHODS = data[1];
      read_from(in_socket_, NMETHODS, [this, complete](bytes& data) {
        // return X'00' NO AUTHENTICATION REQUIRED
        bytes resp = {0x05, 0x00};
        write_to(in_socket_, resp, [this, complete]() {
          if (complete) complete();
        });
      });
    });
  }

  void handle_socks5_request(function<void(string host, string port)> complete) {
    read_from(in_socket_, 4, [this, complete](bytes& data) {
      // CONNECT X'01' BIND X'02' UDP ASSOCIATE X'03'
      b1 VER = data[0];  // 0x05
      b1 CMD = data[1];
      b1 ATYP = data[3];
      if (ATYP == 0x01) {
        // IP V4 address + port
        read_from(in_socket_, 4, [this, complete](bytes& data) {
          b4 ipv4 = get_b4(data, 0);
          b2 port = get_b2_big_endian(data, 4);
          string hoststr = boost::asio::ip::address_v4(ipv4).to_string();
          string portstr = std::to_string(port);
          if (complete) complete(hoststr, portstr);
        });
      } else if (ATYP == 0x03) {
        // DOMAINNAME, The first octet contains the number of octets of name
        // that follow, there is no terminating NUL octet.
        read_from(in_socket_, 1, [this, complete](bytes& data) {
          b1 dnlen = data[0];
          read_from(in_socket_, dnlen + 2, [this, complete, dnlen](bytes& data) {
            std::string hoststr = string_from_bytes(data, 0, data.size() - 2);
            b2 port = get_b2_big_endian(data, dnlen);
            string portstr = std::to_string(port);
            if (complete) complete(hoststr, portstr);
          });
        });
      } else if (ATYP == 0x04) {
        return err("NOT IMPL: Support IPv6 ");
      } else {
        return err("Request ATYP wrong value: " + std::to_string(ATYP));
        ;
      }
    });
  }

  void write_socks5_response(function<void(void)> complete) {
    bytes dt = {0x05 /*ver*/, 0x00 /*succ*/, 0x00};
    push_b1(dt, 0x01);  // ipv4 type
    // remote ipv4 and port
    b4 realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_uint();
    b2 realRemoteport = out_socket_.remote_endpoint().port();
    push_b4_big_endian(dt, realRemoteIP);
    push_b2_big_endian(dt, realRemoteport);
    write_to(in_socket_, dt, [this, complete]() {
      if (complete) complete();
    });
  }

  asio::io_service& io_context_;
  tcp::socket in_socket_;
  tcp::socket out_socket_;
  tcp::resolver resolver_;
  luke::crypto crp_;

  bytes dt_;
  function<void(void)> session_exit_handler = nullptr;
};

}  // namespace luke
