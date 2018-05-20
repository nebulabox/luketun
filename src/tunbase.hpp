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
  ~tun_session_base() { log_info("Dealloc", "tun_session_base"); }
  tun_session_base(asio::io_service &io_context, tcp::socket socket)
      : io_context_(io_context), in_socket_(std::move(socket)),
        out_socket_(io_context), resolver(io_context), crp("@@abort();") {}

  const bytes encode_pkg(b4 cmd_or_result, b4 id, b4 flags,
                         const bytes &body_data) {
    bytes ret;
    bytes encrpyt_body;
    crp.encrypt(body_data, encrpyt_body);
    bytes header_data;
    push_b4(header_data, VER);
    push_b4(header_data, cmd_or_result);
    push_b4(header_data, id);
    push_b4(header_data, flags);
    push_b4(header_data, (b4)encrpyt_body.size()); // crypto body size
    bytes encrpyt_header;
    crp.encrypt(header_data, encrpyt_header);
    push_b2(ret, (b2)encrpyt_header.size()); // header length
    push_bytes(ret, encrpyt_header);
    push_bytes(ret, encrpyt_body);
    return ret;
  }

  void close_sockets() {
    try {
      in_socket_.close();
      out_socket_.close();
    } catch (...) {
    }
  }

  void err(const std::string msg, const std::error_code ec) {
    close_sockets();
    log_err(msg, ec);
  }

  void err(const std::string msg) {
    std::error_code ec;
    close_sockets();
    log_err(msg, ec);
  }

  void decode_pkg(tcp::socket &sk,
                  function<void(bool succ, tun_pkg &pkg)> handler) {
    tun_pkg pkg;
    bytes data;
    data.resize(2);
    asio::async_read(
        sk, asio::buffer(data, 2), [&](std::error_code ec, std::size_t length) {
          if (ec || length != 2) {
            err("Read header len", ec);
            return handler(false, pkg);
          }
          b2 header_len = get_b2(data, 0);
          data.resize(header_len);
          asio::async_read(sk, asio::buffer(data, header_len),
                           [&](std::error_code ec, std::size_t length) {
                             if (ec || length != header_len) {
                               err("Read header data", ec);
                               return handler(false, pkg);
                             }
                             // decrpyt header
                             bytes header;
                             crp.decrypt(data, header);
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
                             data.resize(body_len);
                             asio::async_read(
                                 sk, asio::buffer(data, body_len),
                                 [&](std::error_code ec, std::size_t length) {
                                   if (ec || length != body_len) {
                                     err("Read body data", ec);
                                     return handler(false, pkg);
                                   }
                                   // decrpyt body
                                   crp.decrypt(data, pkg.body);
                                   //  dump_bytes("[out]body", body);
                                   // cout << string_from_bytes(body);
                                   handler(true, pkg);
                                 });
                           });
        });
  }

  void write_to(tcp::socket &sk, bytes &bs, function<void(bool succ)> handler) {
    boost::asio::async_write(
        sk, boost::asio::buffer(bs, bs.size()),
        [&](boost::system::error_code ec, std::size_t length) {
          if (ec) {
            err("Write to", ec);
            return handler(false);
          }
          handler(true);
        });
  }

  void read_from(tcp::socket &sk,
                 function<void(bool succ, bytes &data)> handler) {
    // read any bytes
    bytes dt;
    dt.resize(MAX_BUF_SIZE);
    sk.async_receive(boost::asio::buffer(dt, MAX_BUF_SIZE),
                     [&](boost::system::error_code ec, std::size_t length) {
                       if (ec) {
                         err("read from", ec);
                         return handler(false, dt);
                       }
                       dt.resize(length);
                       handler(true, dt);
                     });
  }

  void read_from(tcp::socket &sk, size_t count,
                 function<void(bool succ, bytes &data)> handler) {
    // read certain numbers
    bytes dt;
    dt.resize(count);
    asio::async_read(sk, boost::asio::buffer(dt, count),
                     [&](boost::system::error_code ec, std::size_t length) {
                       if (ec) {
                         err("read from", ec);
                         return handler(false, dt);
                       }
                       if (length != count) {
                         err("read from length != count", ec);
                         return handler(false, dt);
                       }
                       handler(true, dt);
                     });
  }

  void
  resolve_addr(string host, string port,
               function<void(bool succ, tcp::resolver::iterator it)> handler) {
    resolver.async_resolve(
        tcp::resolver::query(host, port),
        [&](const boost::system::error_code &ec, tcp::resolver::iterator it) {
          if (ec) {
            err("Resolve", ec);
            return handler(false, it);
          }
          handler(true, it);
        });
  }

  void connect_to(tcp::socket &sk,
                  const tcp::resolver::results_type::iterator &it,
                  function<void(bool)> complete) {
    sk.async_connect(*it, [&](const boost::system::error_code &ec) {
      if (ec) {
        log_err("Failed to connect", ec);
        return complete(false);
      }
      return complete(true);
    });
  }

  asio::io_service &io_context_;
  tcp::socket in_socket_;
  tcp::socket out_socket_;
  tcp::resolver resolver;
  luke::crypto crp;
};

} // namespace luke
