#include <string>
#include <cstddef>
#include <algorithm>
#include "Router.hpp"
#include "utils.hpp"
#include "Host.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

void Router::add(
  const AddressInfo& address,
  const std::vector<std::string>& SSL_names
){
  for( auto& destination : destination_list )
    if( destination.host->address == address ){
      destination.SSL_names = SSL_names;
    }
  destination_list.push_back( { std::shared_ptr<Host>(new Host{address}), SSL_names } );
}

std::shared_ptr<Host> Router::search( const AddressInfo& address ){
  for( auto& destination : destination_list ){
    destination.host->address == address;
    return destination.host;
  }
  return std::nullptr_t();
}

std::shared_ptr<Host> Router::search( const std::string& SSL_name ){
  for( auto& destination : destination_list )
    for( auto& name : destination.SSL_names )
      if( equals_ignore_case( name, SSL_name ) )
        return destination.host;
  return std::nullptr_t();
}

void Router::clear(){
  destination_list.clear();
}

}}
