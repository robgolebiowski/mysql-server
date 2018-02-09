#ifndef SMART_LOOP_GKMS_TOKEN_H
#define SMART_LOOP_GKMS_TOKEN_H

#include <my_global.h>
#include "gkms_curl.h"
#include "gkms_conf_parser.h"

namespace keyring
{

class Gkms_token
{
public:
  Gkms_token(ILogger *logger, ConfMap &conf_map)
    : logger(logger)
    , conf_map(conf_map)
  {}

  Secure_string get_token(std::string &token); //TODO: Change to Secure_string

protected:
  //uint get_current_unix_timestamp();
  //uint get_unix_timestamp_in_future(uint timestamp, uint seconds_to_add);

  virtual std::string get_request_body();
  Secure_string get_encoded_header();
  Secure_string get_encoded_body();
  Secure_string get_sha256_request_dgst();

  std::string request_header = R"({"alg":"RS256","typ":"JWT"})";
  //std::string request_body;
  ILogger *logger;
  ConfMap conf_map;

  //struct Request_body
  //{
    //std::string scope = R"("scope":"https://www.googleapis.com/auth/cloudkms")";
    //std::string aud = R"("aud":"https://www.googleapis.com/oauth2/v4/token")";
    //std::string iss;
    //std::string exp;
    //std::string iat;
  //};
};

} //namespace keyring

#endif //SMART_LOOP_GKMS_TOKEN_H

