#include <string>
#include <cstddef>
#include <algorithm>
#include "Router.hpp"
#include "Host.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

template <typename T>
bool compare_ignore_case( T a, T b ){
  return std::tolower(a) == std::tolower(b);
}

template <typename T>
bool equals_ignore_case( std::basic_string<T> const& a, std::basic_string<T> const& b ){
  return std::equal( b.begin(), b.end(), a.begin(), compare_ignore_case<T> );
}
void Router::add(
  const std::string& host,
  const std::vector<std::string>& SSL_names
){
  add( std::shared_ptr<Host>(new Host{host}), SSL_names );
}

void Router::add(
  std::shared_ptr<Host> host,
  const std::vector<std::string>& SSL_names
){
  destination_list.push_back( { host, SSL_names } );
}

std::shared_ptr<Host> Router::search( const std::string& SSL_name ){
  for( auto& destination : destination_list )
    for( auto& name : destination.SSL_names )
      if( equals_ignore_case( name, SSL_name ) )
        return destination.host;
  return std::nullptr_t();
}

}}
