#ifndef DPA_SSL_SNI_FORWARDER_HOST
#define DPA_SSL_SNI_FORWARDER_HOST

#include <string>
#include <ctime>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace DPA {
namespace SSL_SNI_Forwarder {

class Host {
  public:
    const std::string name;
    const std::string protocol;

  public:
    Host( const std::string&, const std::string& ="443" );
    ~Host();
    int connect();

};

}}

#endif