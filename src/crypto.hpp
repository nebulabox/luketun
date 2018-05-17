#pragma once 

#include "common.hpp"
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>

namespace luke {
typedef b4 uInt32;

#define MAXKEYBYTES 56 /* 448 bits */

typedef struct {
  uInt32 P[16 + 2];
  uInt32 S[4][256];
} BLOWFISH_CTX;

void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, b4 *xl, b4 *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, b4 *xl, b4 *xr);

class crypto {
public:
  BLOWFISH_CTX ctx;

  crypto(const std::string key) {
    Blowfish_Init(&ctx, (unsigned char *)(key.data()), (int)key.size());
  }

  const bytes zlib_compress(const bytes &input) {
    using namespace boost::iostreams;
    array_source arr_src(reinterpret_cast<char const*>(input.data()), input.size());
    filtering_istreambuf in;
    in.push(zlib_compressor());
    in.push(arr_src);
    return bytes(std::istreambuf_iterator<char>{&in}, {});
  }

  const bytes zlib_decompress(const bytes &input) {
    using namespace boost::iostreams;
    array_source arr_src(reinterpret_cast<char const*>(input.data()), input.size());
    filtering_istreambuf in;
    in.push(zlib_decompressor());
    in.push(arr_src);
    return bytes(std::istreambuf_iterator<char>{&in}, {});
  }

  const bytes encrypt(const bytes &input) {
    // input -> zlib -> blowfish
    bytes dt = zlib_compress(input);
    bytes ret;
    b4 L, R;
    // first 4 bytes is the real data length
    b4 len = (b4)dt.size();
    // then 4 bytes is reserved
    b4 reserved = 0;
    L = len;
    R = reserved;
    Blowfish_Encrypt(&ctx, &L, &R);
    push_b4(ret, L);
    push_b4(ret, R);
    int pos = 0;
    while ((pos + 8) < len) {
      L = get_b4(dt, pos);
      R = get_b4(dt, pos + 4);
      Blowfish_Encrypt(&ctx, &L, &R);
      push_b4(ret, L);
      push_b4(ret, R);
      pos += 8;
    }
    bytes left;
    while (pos < len) {
      left.push_back(dt[pos]);
      pos++;
    }
    while ((left.size() % 8) != 0) {
      left.push_back(0);
    }
    if (left.size() > 0) {
      L = get_b4(left, 0);
      R = get_b4(left, 4);
      Blowfish_Encrypt(&ctx, &L, &R);
      push_b4(ret, L);
      push_b4(ret, R);
    }
    return ret;
  }

  const bytes decrypt(const bytes &dt) {
    // blowfish -> zlib -> bytes
    if ((dt.size() % 8) != 0) {
      std::cerr << "decrypt need 8 bytes pad" << std::endl;
      return bytes();
    }
    bytes ret;
    b4 L, R;
    b4 len;
    for (auto pos = 0; pos < dt.size(); pos += 8) {
      L = get_b4(dt, pos);
      R = get_b4(dt, pos + 4);
      Blowfish_Decrypt(&ctx, &L, &R);
      if (pos == 0) {
        len = L;
      } else {
        push_b4(ret, L);
        push_b4(ret, R);
      }
    }
    ret.resize(len);

    return zlib_decompress(ret);
  }

  static void test() {
    b4 L = 1, R = 2;
    BLOWFISH_CTX ctx;
    Blowfish_Init(&ctx, (unsigned char *)"TESTKEY", 7);
    Blowfish_Encrypt(&ctx, &L, &R);
    if (L == 0xDF333FD2L && R == 0x30A71BB4L)
      printf("Test encryption OK.\n");
    else
      printf("Test encryption failed.\n");
    Blowfish_Decrypt(&ctx, &L, &R);
    if (L == 1 && R == 2)
      printf("Test 1 OK.\n");
    else
      printf("Test 1 failed.\n");
      
    std::string key = "abcdefghijklmnopqrstuvwxyz";
    crypto bf(key);
    bytes dt = bytes_from_string("BLOWFISH IS COOL!");
    if (bf.decrypt(bf.encrypt(dt)) == dt) {
      printf("Test 2 OK.\n");
    } else {
      printf("Test 2 failed.\n");
    }
    dt = bytes_from_string("BLOWFISH");
    if (bf.decrypt(bf.encrypt(dt)) == dt) {
      printf("Test 3 OK.\n");
    } else {
      printf("Test 3 failed.\n");
    }
    dt = bytes_from_string("BLOWFISH1234567");
    if (bf.decrypt(bf.encrypt(dt)) == dt) {
      printf("Test 4 OK.\n");
    } else {
      printf("Test 4 failed.\n");
    }
  }
};

} // namespace luke
