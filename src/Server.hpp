#ifndef DPA_SSL_SNI_FORWARDER_SERVER
#define DPA_SSL_SNI_FORWARDER_SERVER

#include <vector>
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

      Router router;

      Server( const AddressInfo& address );
      virtual ~Server();

      void run();
      void addToSet( fd_set& read_set, fd_set& write_set, int& maxfd );
      void process( fd_set& read_set, fd_set& write_set );
      const char* getLastError();
      const AddressInfo& getAddress();

  };

}}

#endif
