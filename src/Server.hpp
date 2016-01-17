#ifndef DPA_SSL_SNI_FORWARDER_SERVER
#define DPA_SSL_SNI_FORWARDER_SERVER

#include <vector>
#include <memory>
#include "Router.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "utils.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  class Client;

  class Server {
    friend class Client;
    private:
      const AddressInfo address;
      struct addrinfo* address_results = 0;
      struct addrinfo* address_result  = 0;
      int socket = -1, maxfd = -1;
      const char* error = 0;
      bool valid = false;
      bool acceptClient();
      std::vector<Client*> clients;

      void remove(Client*);

    public:

      std::shared_ptr<Router> router;

      Server(
        const AddressInfo& address,
        std::shared_ptr<Router> router = std::shared_ptr<Router>(new Router())
      );
      virtual ~Server();

      void run();
      void addToSet( fd_set& set, int& maxfd );
      void process( fd_set& set );
      const char* getLastError();
      const AddressInfo& getAddress();

  };

}}

#endif
