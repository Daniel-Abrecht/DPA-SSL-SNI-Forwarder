#ifndef DPA_SSL_SNI_FORWARDER_ROUTER
#define DPA_SSL_SNI_FORWARDER_ROUTER

#include <vector>
#include <string>
#include <memory>

namespace DPA {
namespace SSL_SNI_Forwarder {

class Host;
class Router {
  struct Destination {
    std::shared_ptr<Host> host;
    const std::vector<std::string> SSL_names;
  };
  private:
    std::vector<Destination> destination_list;
  public:
    std::shared_ptr<Host> default_destination;
    void add( const std::string& host, const std::vector<std::string>& SSL_names );
    void add( std::shared_ptr<Host> host, const std::vector<std::string>& SSL_names );
    std::shared_ptr<Host> search( const std::string& SSL_name );
};

}}

#endif