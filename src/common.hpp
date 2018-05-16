#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <chrono>
#include <codecvt>
#include <cstddef>
#include <cstdlib>
#include <deque>
#include <exception>
#include <forward_list>
#include <iomanip>
#include <iostream>
#include <list>
#include <memory>
#include <pthread.h>
#include <queue>
#include <random>
#include <regex>
#include <sstream>
#include <stack>
#include <streambuf>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "const.hpp"

#define BOOST_ASIO_NO_DEPRECATED
#include <boost/asio.hpp>

// Debug Options
#ifdef DEBUG
// more detail output for every push and get binary
//#define ENABLE_STEP_OUTPUT_BYTES 1

// enable dump bytes for debug
#define ENABLE_DUMP_BYTES 1
#endif // DEBUG

// Some Macro Utils
#define NOT_IMPL throw std::logic_error("NOT IMPL")
#define throw_msg(msg) throw std::logic_error(msg)

namespace luke {

typedef std::vector<std::string> vs;
typedef std::vector<uint8_t> bytes;
typedef uint8_t b1;
typedef uint16_t b2;
typedef uint32_t b4;
typedef uint64_t b8;

inline void log_info(const std::string notes, const std::string msg) {
#ifdef DEBUG
  std::cout << "[INFO]" << notes << ": " << msg << std::endl;
#endif
}

inline void log_err(const std::string notes, const std::string msg) {
  std::cerr << "[ERROR]" << notes << ": " << msg << std::endl;
}

inline void log_err(std::string msg) { std::cerr << "[ERROR]" << msg << std::endl; }

inline void log_err(std::string msg, std::error_code ec) {
  std::cerr << "[ERROR]" << msg << " : " << ec.message() << std::endl;
}

inline void dump(vs &data) {
#ifdef DEBUG
  std::cout << "Begin Dump Vector String ========" << std::endl;
  for (int i = 0; i < data.size(); i++) {
    std::cout << data[i] << ", ";
  }
  std::cout << std::endl
            << "Total Count = " << data.size() << std::endl
            << "End Dump Vector String ==========" << std::endl;
#endif
}

inline bool isspace(int _c) {
  return (std::isspace((char)_c, std::locale("C")) == 0) || (_c == 0);
}

// trim from start
inline std::string &ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                  [](int c) { return luke::isspace(c); }));
  return s;
}

// trim from end
inline std::string &rtrim(std::string &s) {
  auto it = std::find_if(s.rbegin(), s.rend(),
                         [](int c) { return luke::isspace(c); });
  s.erase(it.base(), s.end());
  return s;
}

// trim from both ends
inline std::string &trim(std::string &s) { return ltrim(rtrim(s)); }

inline std::string toupper(const std::string str) {
  std::string ret = str;
  for (auto &c : ret)
    c = std::toupper(c);
  return ret;
}

inline std::string hex_string(int64_t i) {
  std::stringstream ss;
  ss << "0x" << std::hex << i;
  return toupper(ss.str());
}

inline std::string to_string(int64_t i) {
  std::stringstream ss;
  ss << std::dec << i;
  return ss.str();
}

inline std::string last_path_component(std::string s) {
  return s.substr(s.find_last_of("/\\") + 1);
}

inline bool starts_with(const std::string &s, const std::string &prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string &s, const std::string &suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), s.size(), suffix) == 0;
}

inline std::vector<std::string> split(std::string str, std::string pattern) {
  std::vector<std::string> ret;
  std::regex rgx(pattern);
  // http://en.cppreference.com/w/cpp/regex/regex_token_iterator/regex_token_iterator
  auto iter = std::sregex_token_iterator(str.begin(), str.end(), rgx, -1);
  auto end = std::sregex_token_iterator();
  for (; iter != end; iter++) {
    ret.push_back(*iter);
  }
  return ret;
}

inline void dump_bytes_force(const std::string notes, const bytes &v) {
  std::cout << "------------------------------------" << std::endl;
  std::cout << "[DEBUG]" << notes << ": size=" << std::dec << v.size()
            << std::endl;

  int num = 0;
  for (int i = 0; i < v.size(); i++) {
    if ((num++ % 16) == 0) {
      std::cout << std::endl;
      std::cout << std::setw(4) << std::hex << (num / 10) << "|";
    }
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(v[i])
              << " ";
    if (num % 16 == 8) {
      std::cout << "  ";
    }
  }
  std::cout << std::endl << std::endl;
}

inline void dump_bytes(const std::string notes, const bytes &v) {
#if defined(ENABLE_DUMP_BYTES) || defined(ENABLE_STEP_OUTPUT_BYTES)
  dump_bytes_force(notes, v);
#endif
}

inline void push_string(bytes &v, const std::string str) {
  std::copy(str.begin(), str.end(), std::back_inserter(v));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_string", v);
#endif
}

inline void push_bytes(bytes &v, const bytes arr) {
  std::copy(arr.begin(), arr.end(), std::back_inserter(v));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_bytes", v);
#endif
}
inline void push_bytes(bytes &v, const b1 *arr, const size_t len) {
  std::copy(arr, arr + len, std::back_inserter(v));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_bytes", v);
#endif
}

inline void push_b1(bytes &v, const uint8_t uchar) {
  v.push_back(uchar);
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_b1", v);
#endif
}

inline void push_b2(bytes &v, const uint16_t u16) {
  // little endian
  v.push_back(u16 & 0x00FF);
  v.push_back((u16 & 0xFF00) >> 8);
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_b2", v);
#endif
}

inline void push_b2_big_endian(bytes &v, const uint16_t u16) {
  v.push_back((u16 & 0xFF00) >> 8);
  v.push_back((u16 & 0x00FF));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_b2_big_endian", v);
#endif
}

inline void push_b4(bytes &v, const uint32_t u32) {
  v.push_back(u32 & 0x000000FF);
  v.push_back((u32 & 0x0000FF00) >> 8);
  v.push_back((u32 & 0x00FF0000) >> 16);
  v.push_back((u32 & 0xFF000000) >> 24);
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_b4", v);
#endif
}

inline void push_b4_big_endian(bytes &v, const uint32_t u32) {
  v.push_back((u32 & 0xFF000000) >> 24);
  v.push_back((u32 & 0x00FF0000) >> 16);
  v.push_back((u32 & 0x0000FF00) >> 8);
  v.push_back(u32 & 0x000000FF);
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_b4_big_endian", v);
#endif
}

inline void push_b8(bytes &v, const uint64_t u64) {
  v.push_back((b1)((u64 & 0x00000000000000FF)));
  v.push_back((b1)((u64 & 0x000000000000FF00) >> 8));
  v.push_back((b1)((u64 & 0x0000000000FF0000) >> 16));
  v.push_back((b1)((u64 & 0x00000000FF000000) >> 24));
  v.push_back((b1)((u64 & 0x000000FF00000000) >> 32));
  v.push_back((b1)((u64 & 0x0000FF0000000000) >> 40));
  v.push_back((b1)((u64 & 0x00FF000000000000) >> 48));
  v.push_back((b1)((u64 & 0xFF00000000000000) >> 56));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("push_b8", v);
#endif
}

inline uint8_t get_b1(const bytes &v, const int begin) {
  if (begin < 0 || (begin + 1) > v.size()) {
    throw std::range_error("get_b1 out of range");
  }
#ifdef ENABLE_STEP_OUTPUT_BYTES
  std::cout << std::dec << "get_b1=" << v[begin] << std::endl;
#endif
  return v[begin];
}

inline uint16_t get_b2(const bytes &v, const int begin) {
  if (begin < 0 || (begin + 2) > v.size()) {
    throw std::range_error("get_b2 out of range");
  }
  uint16_t v0 = uint16_t(v[begin]) | 0xFF00;
  uint16_t v1 = uint16_t(v[begin + 1]) << 8 | 0x00FF;
#ifdef ENABLE_STEP_OUTPUT_BYTES
  std::cout << std::dec << "get_b2=" << (v0 & v1) << std::endl;
#endif
  return (v0 & v1);
}

inline uint16_t get_b2_big_endian(const bytes &v, const int begin) {
  if (begin < 0 || (begin + 2) > v.size()) {
    throw std::range_error("get_b2_big_endian out of range");
  }
  uint16_t v0 = uint16_t(v[begin]) << 8 | 0x00FF;
  uint16_t v1 = uint16_t(v[begin + 1]) | 0xFF00;
#ifdef ENABLE_STEP_OUTPUT_BYTES
  std::cout << std::dec << "get_b2_big_endian =" << (v0 & v1) << std::endl;
#endif
  return (v0 & v1);
}

inline uint32_t get_b4(const bytes &v, const int begin) {
  if (begin < 0 || (begin + 4) > v.size()) {
    throw std::range_error("get_b4 out of range");
  }
  uint32_t v0 = uint32_t(v[begin]) | 0xFFFFFF00;
  uint32_t v1 = uint32_t(v[begin + 1]) << 8 | 0xFFFF00FF;
  uint32_t v2 = uint32_t(v[begin + 2]) << 16 | 0xFF00FFFF;
  uint32_t v3 = uint32_t(v[begin + 3]) << 24 | 0x00FFFFFF;
#ifdef ENABLE_STEP_OUTPUT_BYTES
  std::cout << std::dec << "get_b4=" << (v0 & v1 & v2 & v3) << std::endl;
#endif
  return (v0 & v1 & v2 & v3);
}

inline uint32_t get_b4_big_endian(const bytes &v, const int begin) {
  if (begin < 0 || (begin + 4) > v.size()) {
    throw std::range_error("get_b4_big_endian out of range");
  }
  uint32_t v0 = uint32_t(v[begin]) << 24 | 0x00FFFFFF;
  uint32_t v1 = uint32_t(v[begin + 1]) << 16 | 0xFF00FFFF;
  uint32_t v2 = uint32_t(v[begin + 2]) << 8 | 0xFFFF00FF;
  uint32_t v3 = uint32_t(v[begin + 3]) | 0xFFFFFF00;
  uint32_t ret = v0 & v1 & v2 & v3;
#ifdef ENABLE_STEP_OUTPUT_BYTES
  std::cout << std::dec << "get_b4_big_endian=" << ret << std::endl;
#endif
  return ret;
}

inline uint64_t get_b8(const bytes &v, const int begin) {
  if (begin < 0 || (begin + 8) > v.size()) {
    throw std::range_error("get_b8 out of range");
  }
  uint64_t v0 = uint64_t(v[begin]) | 0xFFFFFFFFFFFFFF00;
  uint64_t v1 = uint64_t(v[begin + 1]) << 8 | 0xFFFFFFFFFFFF00FF;
  uint64_t v2 = uint64_t(v[begin + 2]) << 16 | 0xFFFFFFFFFF00FFFF;
  uint64_t v3 = uint64_t(v[begin + 3]) << 24 | 0xFFFFFFFF00FFFFFF;
  uint64_t v4 = uint64_t(v[begin + 4]) << 32 | 0xFFFFFF00FFFFFFFF;
  uint64_t v5 = uint64_t(v[begin + 5]) << 40 | 0xFFFF00FFFFFFFFFF;
  uint64_t v6 = uint64_t(v[begin + 6]) << 48 | 0xFF00FFFFFFFFFFFF;
  uint64_t v7 = uint64_t(v[begin + 7]) << 56 | 0x00FFFFFFFFFFFFFF;
#ifdef ENABLE_STEP_OUTPUT_BYTES
  std::cout << std::dec << "get_b8=" << (v0 & v1 & v2 & v3 & v4 & v5 & v6 & v7)
            << std::endl;
#endif
  return (v0 & v1 & v2 & v3 & v4 & v5 & v6 & v7);

  return (uint64_t)v[begin] & ((uint64_t)v[begin + 1] << 8) &
         ((uint64_t)v[begin + 2] << 16) & ((uint64_t)v[begin + 3] << 24) &
         ((uint64_t)v[begin + 4] << 32) & ((uint64_t)v[begin + 5] << 40) &
         ((uint64_t)v[begin + 6] << 48) & ((uint64_t)v[begin + 7] << 56);
}

inline bytes get_bytes(const bytes &v, const int begin, const size_t length) {
  if (length == 0)
    return bytes();

  if (begin < 0 || (begin + length) > v.size()) {
    throw std::range_error("get_bytes out of range");
  }
  bytes bs;
  bs.reserve(length);
  std::copy(v.begin() + begin, v.begin() + begin + length,
            std::back_inserter(bs));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("get_bytes", bs);
#endif
  return bs;
}

inline bytes get_bytes(const bytes &v, const int begin) {
  if (begin < 0 || begin >= v.size()) {
    return bytes();
  }
  bytes bs;
  std::copy(v.begin() + begin, v.end(), std::back_inserter(bs));
#ifdef ENABLE_STEP_OUTPUT_BYTES
  dump_bytes("get_bytes", bs);
#endif
  return bs;
}

inline bytes concat(const bytes &a, const bytes &b) {
  bytes ret;
  ret.reserve(a.size() + b.size());
  std::copy(a.begin(), a.end(), std::back_inserter(ret));
  std::copy(b.begin(), b.end(), std::back_inserter(ret));
  return ret;
}

inline bytes operator+(const bytes &a, const bytes &b) {
  bytes ret;
  ret.reserve(a.size() + b.size());
  std::copy(a.begin(), a.end(), std::back_inserter(ret));
  std::copy(b.begin(), b.end(), std::back_inserter(ret));
  return ret;
}

inline b1 rand_b1() { return b1(rand() % 255); }

inline bytes bytes_from_string(const std::string &str) {
  bytes ret;
  for (char c : str) {
    ret.push_back(c);
  }
  return ret;
}

inline std::string string_from_bytes(const bytes &bs) {
  std::string ret;
  ret.resize(bs.size());
  for (int i = 0; i < bs.size(); i++) {
    ret[i] = bs[i];
  }

  return ret;
}
} // namespace luke
