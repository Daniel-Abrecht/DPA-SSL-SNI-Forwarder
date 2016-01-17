#ifndef DPA_SSL_SNI_FORWARDER_CLIENT
#define DPA_SSL_SNI_FORWARDER_CLIENT

#include <cstddef>
#include <string>

namespace DPA {
namespace SSL_SNI_Forwarder {

  enum ServerNameType {
    SNT_host_name
  };

  struct ServerNameEntry {
    enum ServerNameType type;
    std::string name;
  };

  class Server;
  class Client {

    private:
      Server* server;
      int socket = -1, destination = -1;
      struct sockaddr_storage address;
      socklen_t address_length;
      static constexpr const size_t buffer_size = 1024 * 4;
      unsigned char* buffer = 0;
      size_t offset = 0;
      std::vector<ServerNameEntry> serverNameList;

      void tunnel( fd_set& set );
      void determinateDestination();

    public:

      Client( Server*, int, struct sockaddr_storage&, socklen_t );
      virtual ~Client();
      void addToSet( fd_set& set, int& maxfd );
      void process( fd_set& set );
      void close();
      void forward();

  };

}}

#endif
