#include "common.hpp"
#include "crypto.hpp"
#include "tunclient.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  try {
    boost::asio::io_service io_context;
	luke::socks5_server s(io_context, 8181);
    //luke::tun_client s(io_context, 8181);
    cout << "Local server started on port 8181" << endl;
    io_context.run();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
