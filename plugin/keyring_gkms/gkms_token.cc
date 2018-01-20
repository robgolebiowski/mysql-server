#include "gkms_token.h"
#include "gkms_curl.h"
#include <time.h>
#include <chrono>

namespace keyring
{

bool Gkms_token::get_token(std::string &token)
{
  return true;
}

std::string Gkms_token::get_request_body()
{
  std::ostringstream request_body_ss;
  request_body_ss << "{";
  request_body_ss << R"("iss":")" << conf_map["iss"] << R"(",)";
  request_body_ss << R"("scope":")" << conf_map["scope"] << R"(",)";
  request_body_ss << R"("aud":")" << conf_map["aud"] << R"(",)";
  auto unix_timestamp = std::chrono::seconds(std::time(NULL));
  request_body_ss << R"("iat":)" << unix_timestamp.count() << R"(",)";
  request_body_ss << R"("exp":)" << unix_timestamp.count() + 3600 << R"(",)"; //TODO: exp time is one hour in the future - should it be configurable ?
  request_body_ss << R"("private_key":")" << conf_map["private_key"] << R"(")";
  request_body_ss << "}";

  return request_body_ss.str();
}

//uint get_current_unix_timestamp()
//{
  //auto unix_timestamp = std::chrono::seconds(std::time(NULL));

//}


} //namespace keyring
