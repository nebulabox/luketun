#include "common.hpp"
#include "const.hpp"
#include "tunserver.hpp"

using namespace std;

bool luke::global_config::enable_log_info = true;
bool luke::global_config::enable_log_err = true;

int main(int argc, char *argv[]) {
  try {
    boost::asio::io_service io_context;

    luke::tun_server s(io_context, 2484);
    cout << "tun server started on port 2484" << endl;

    io_context.run();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
