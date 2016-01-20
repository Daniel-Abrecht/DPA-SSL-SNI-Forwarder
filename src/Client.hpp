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
      AddressInfo destination_address;
      struct sockaddr_storage address;
      struct addrinfo* address_results = 0;
      struct addrinfo* addr = 0;
      socklen_t address_length;
      static constexpr const size_t buffer_size = 1024 * 8;
      unsigned char buffer[buffer_size];
      size_t write_offset = 0;
      size_t read_offset = 0;
      std::vector<ServerNameEntry> serverNameList;

      bool read_or_write = true;
      bool source_or_destination = true;

      void (Client::*next_action)() = &Client::determinateDestination;

      void determinateDestination();
      void lookupDestinationAddress();
      void send();
      void connect();
      void recive();


    public:

      Client( Server*, int, struct sockaddr_storage&, socklen_t );
      virtual ~Client();
      void addToSet( fd_set& read_set, fd_set& write_set, int& maxfd );
      void process( fd_set& read_set, fd_set& write_set );
      void close();
      void forward();

  };

}}

#endif
