#include "common.hpp"
#include "crypto.hpp"
#include "tunclient.hpp"

using namespace std;

int main(int argc, char *argv[]) {
  try {
    boost::asio::io_context io_context;
    luke::tun_client s(io_context, 8181);
    cout << "Tun client local server started on port 8181" << endl;
    io_context.run();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
