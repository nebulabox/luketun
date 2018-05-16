#include "common.hpp"
#include "socks5.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  try {
    boost::asio::io_context io_context;

    luke::socks5_server s(io_context, 8181);

    cout << "Socks5 server started on port 8181" << endl;

    io_context.run();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
