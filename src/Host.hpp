#ifndef DPA_SSL_SNI_FORWARDER_HOST
#define DPA_SSL_SNI_FORWARDER_HOST

#include <string>
#include <ctime>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "utils.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

class Host {
  public:
    AddressInfo address;

    Host( const AddressInfo& );
    ~Host();
    int connect();

};

}}

#endif