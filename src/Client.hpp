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
    ServerNameEntry( enum ServerNameType type, std::string&& name )
     : type(type), name(name)
    {}
  };
  
  class Server;
  class Client {

    private:
      Server* server;
      int socket;
      struct sockaddr_storage address;
      socklen_t address_length;
      static constexpr const size_t buffer_size = 1024 * 4;
      unsigned char buffer[ buffer_size ];
      size_t offset;
      std::vector<ServerNameEntry> serverNameList;

    public:

      Client( Server*, int, struct sockaddr_storage, socklen_t );
      virtual ~Client();
      void addToSet( fd_set& set, int& maxfd );
      bool isSet( fd_set& set );
      void process();
      void close();
      
  };

}}

#endif
