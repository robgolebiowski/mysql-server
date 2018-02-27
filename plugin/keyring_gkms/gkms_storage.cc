#include "gkms_storage.h"
#include "gkms_token_receiver.h"
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
  Secure_string key_data(reinterpret_cast<const char*>(key->get_key_data()));
  curl.set_content_length(key->get_key_data_size());
  curl.set_post_data(key_data);

  if (curl.execute())
    return true;
  return false;
}

}
