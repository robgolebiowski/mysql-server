#ifndef SMART_LOOP_GKMS_TOKEN_RECEIVER_H
#define SMART_LOOP_GKMS_TOKEN_RECEIVER_H

#include <my_global.h>
#include "gkms_curl.h"
#include "gkms_conf_parser.h"
#include "gkms_token.h"

namespace keyring
{

class Gkms_token_receiver
{
public:
  Gkms_token_receiver(ILogger *logger, ConfMap &conf_map)
    : logger(logger)
    , conf_map(conf_map)
  {}

  Gkms_token get_token(); //TODO: Change to Secure_string

protected:
  //uint get_current_unix_timestamp();
  //uint get_unix_timestamp_in_future(uint timestamp, uint seconds_to_add);

  virtual std::string get_request_body();
  Secure_string get_encoded_header();
  Secure_string get_encoded_body();
  Secure_string get_sha256_request_dgst(const Secure_string &encoded_request);

  static Secure_string get_value_from_reponse(const Secure_string &key, const Secure_string &response);
  static int get_expires_in_from_reponse(const Secure_string &response);
  static Secure_string get_token_from_reponse(const Secure_string &response);

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

#endif //SMART_LOOP_GKMS_TOKEN_RECEIVER_H

