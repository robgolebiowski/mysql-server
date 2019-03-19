#ifndef SMART_LOOP_GKMS_RESPONSE_PARSER_H
#define SMART_LOOP_GKMS_RESPONSE_PARSER_H

#include <my_global.h>
#include "vault_secure_string.h"

namespace keyring
{

class Gkms_reponse_parser
{
public:
  static Secure_string get_value_from_reponse(const Secure_string &key, const Secure_string &response)
  {
    Secure_string key_marker = R"(")" + key + R"(":)";
    std::size_t token_start_pos = response.find(key_marker);
    if (token_start_pos == std::string::npos)
      return "";
    token_start_pos += key_marker.length();//strnlen(R"("access_token":)", 200);
    token_start_pos = response.find_first_not_of(R"(:" )", token_start_pos);
    if (token_start_pos == std::string::npos)
      return "";
    std::size_t token_end_pos = response.find_first_of("\"\n}", token_start_pos);
    if (token_end_pos == std::string::npos)
      return "";
    return response.substr(token_start_pos, token_end_pos - token_start_pos);
  }

  static bool are_there_errors_in_response(const Secure_string &response, Secure_string &error_code, Secure_string &error_message) {
    if (get_value_from_reponse("error", response) == "") {
      return false;  
    } 
    error_code = get_value_from_reponse("code", response);
    error_message = get_value_from_reponse("message", response);
    return true;
  }

private:
  Gkms_reponse_parser(); // mimic 'static class'
};

} //namespace keyring

#endif //SMART_LOOP_GKMS_RESPONSE_PARSER_H
