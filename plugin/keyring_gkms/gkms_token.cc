#include "gkms_token.h"
#include "gkms_curl.h"
#include <time.h>
#include <chrono>
#include "vault_base64.h"

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
  request_body_ss << R"("private_key":")" << conf_map["private_key"] << R"(",)";
  auto unix_timestamp = std::chrono::seconds(std::time(NULL));
  request_body_ss << R"("iat":)" << unix_timestamp.count() << R"(,)";
  request_body_ss << R"("exp":)" << unix_timestamp.count() + 3600; //TODO: exp time is one hour in the future - should it be configurable ?
  request_body_ss << "}";

  return request_body_ss.str();
}

Secure_string Gkms_token::get_encoded_header()
{
  //bool Vault_base64::encode(const void *src, size_t src_len, Secure_string *encoded, Base64Format format)
  Secure_string encoded_header;
  if (Vault_base64::encode(request_header.c_str(), request_header.length(), &encoded_header, Vault_base64::SINGLE_LINE))
  {
    // TODO: Add logger
    return "";
  }
  return encoded_header;
}

Secure_string Gkms_token::get_encoded_body()
{
  Secure_string encoded_body;
  std::string request_body = get_request_body();
  if (Vault_base64::encode(request_body.c_str(), request_body.length(), &encoded_body, Vault_base64::SINGLE_LINE))
  {
    //TODO: Add logger
    return ""; 
  }
  return encoded_body;
}

//uint get_current_unix_timestamp()
//{
  //auto unix_timestamp = std::chrono::seconds(std::time(NULL));

//}


} //namespace keyring
