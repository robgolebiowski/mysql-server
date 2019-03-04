#include "gkms_storage.h"
#include "gkms_token_receiver.h"
#include "gkms_response_parser.h"
#include "keyring_key.h"

namespace keyring {

bool Gkms_storage::write_key(IKey *key)
{
  Gkms_curl curl(logger);
  Gkms_token_receiver token_receiver(logger, conf_map); // TODO: Change this to some abstraction layer - token will be received when expires
  Gkms_token token = token_receiver.get_token();

  if (curl.init())
    return true;

  Secure_ostringstream oss_url;
  oss_url << "https://www.googleapis.com/upload/storage/v1/b/";
  oss_url << conf_map["bucket_name"];
  oss_url << "/o?uploadType=media&name=";
  oss_url << *(key->get_key_signature());
  Secure_string url = oss_url.str();
  curl.set_url(url);
  //curl.set_token(token.token.c_str());
  curl.set_content_type("Content-Type: text/plain");
  //"Authorization: Bearer [OAUTH2_TOKEN]"
  curl.set_token(token.token);
  Secure_ostringstream oss_key_type_and_data;
  Secure_string key_type(key->get_key_type()->c_str());
  Secure_string key_data(reinterpret_cast<char*>(key->get_key_data()));
  oss_key_type_and_data << R"("type":")" << key_type << R"(",)";
  oss_key_type_and_data << R"("key":")" << key_data << R"(")";
  Secure_string key_type_and_data = oss_key_type_and_data.str();
  //Secure_string key_data(reinterpret_cast<const char*>(key->get_key_data()));
  //curl.set_content_length(key->get_key_data_size());
  //curl.set_post_data(key_data);
  curl.set_post_data(key_type_and_data);

  if (curl.execute())
    return true;

  Secure_string response = curl.get_response();
  Secure_string error_code, error_message;
  if (Gkms_reponse_parser::are_there_errors_in_response(response, error_code, error_message)) {
    //TODO: Add logger;
    return true;
  }
  return false;
}

bool Gkms_storage::get_key(IKey *key)
{
  Gkms_curl curl(logger);
  Gkms_token_receiver token_receiver(logger, conf_map); // TODO: Change this to some abstraction layer - token will be received when expires
  Gkms_token token = token_receiver.get_token();

  if (curl.init())
    return true;

  Secure_ostringstream oss_url;
  oss_url << "https://www.googleapis.com/storage/v1/b/";
  oss_url << conf_map["bucket_name"];
  oss_url << "/o/";
  oss_url << *(key->get_key_signature());
  oss_url << "?alt=media";
  Secure_string url = oss_url.str();
  curl.set_url(url);
  curl.set_content_type("Content-Type: text/plain");
  curl.set_token(token.token);
  curl.set_get_data();

  if (curl.execute())
    return true;

  Secure_string response = curl.get_response();
  Secure_string error_code, error_message;
  if (Gkms_reponse_parser::are_there_errors_in_response(response, error_code, error_message)) {
    //TODO: Add logger;
    return true;
  }

  Secure_string key_type = Gkms_reponse_parser::get_value_from_reponse("type", response);
  if (key_type.empty()) {
    //TODO: Add logger
    return true;
  }

  Secure_string key_data = Gkms_reponse_parser::get_value_from_reponse("key", response);
  if (key_data.empty()) {
    //TODO: Add logger
    return true;
  }

  std::string key_type_str(key_type.c_str());
  key->set_key_type(&key_type_str);
  uchar *key_data_raw = new uchar[key_data.length()+1];
  memcpy(key_data_raw, key_data.c_str(), key_data.length());
  key_data_raw[key_data.length()] = '\0';
  key->set_key_data(key_data_raw, key_data.length());

  return false;
}

}
