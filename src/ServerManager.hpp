#ifndef DPA_SSL_SNI_FORWARDER_SERVERMANAGER
#define DPA_SSL_SNI_FORWARDER_SERVERMANAGER

#include <vector>

namespace DPA {
namespace SSL_SNI_Forwarder {

class Server;
class Client;

class ServerManager {
  private:
    const char* config_file = "/etc/DPA/SSL_SNI_Forwarder.yaml";
    volatile bool keep_running;
    std::vector<Server*> server_list;

  public:
    volatile bool do_reload;

    void setConfigFile( const char* file );
    bool reloadConfig();
    void run();
    void stop();
};

}}

#endif
