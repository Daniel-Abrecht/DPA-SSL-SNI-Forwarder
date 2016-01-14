#ifndef DPA_SSL_SNI_FORWARDER_CLIENT
#define DPA_SSL_SNI_FORWARDER_CLIENT

#include <stddef.h>

namespace DPA {
namespace SSL_SNI_Forwarder {

  class Server;
  class Client {

    private:
      Server* server;
      int socket;
      struct sockaddr_storage address;
      socklen_t address_length;
      char buffer[ 1024 * 4 ];
      size_t offset;

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
