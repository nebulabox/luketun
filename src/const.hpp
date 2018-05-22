#pragma once

namespace luke {
enum { VER=20180517, MAX_BUF_SIZE = 65535 };
enum { OK, ERROR = 1 };
enum { NOPE = 1025, GET_URL, SOCKS_CONNECT };


class global_config {
public:
static bool enable_log_info;
static bool enable_log_err;
};

} // namespace luke
