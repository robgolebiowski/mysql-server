#include <my_global.h>
#include "gkms_curl.h"
#include "gkms_conf_parser.h"

namespace keyring
{

class Gkms_token
{
public:
  Gkms_token(ConfMap &conf_map)
    : conf_map(conf_map)
  {}

  bool get_token(Secure_string &token);

private:
  bool generate_request_body();

  std::string request_header = R"({"alg":"RS256","typ":"JWT"})";
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
