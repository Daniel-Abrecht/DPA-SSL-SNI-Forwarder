#ifndef DPA_SSL_SNI_FORWARDER_SERVER
#define DPA_SSL_SNI_FORWARDER_SERVER

#include <vector>
#include <memory>
#include "Router.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace DPA {
namespace SSL_SNI_Forwarder {

  class Client;
  class Server {
    friend class Client;
    private:
      struct addrinfo* address_results = 0;
      struct addrinfo* address_result  = 0;
      int socket = -1, maxfd = -1;
      const char* error = 0;
      bool valid = false;
      volatile bool keep_running;
      bool acceptClient();
      std::vector<Client*> clients;

    public:

      std::shared_ptr<Router> router;

      Server(
        const char* addr,
        const char* port,
        std::shared_ptr<Router> router = std::shared_ptr<Router>(new Router())
      );
      virtual ~Server();

      void run();
      bool isOK();
      const char* getLastError();
      void stop();
      void remove(Client*);

  };

}}

#endif
