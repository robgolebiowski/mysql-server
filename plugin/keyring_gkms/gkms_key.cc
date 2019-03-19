#include "gkms_key.h"
#include <sstream>

namespace keyring {

my_bool Gkms_key::get_next_key(IKey **key)
{
  if (was_key_retrieved)
  {
    *key = NULL;
    return TRUE;
  }
  *key = new Gkms_key(*this);
  was_key_retrieved = true;
  return FALSE;
}

my_bool Gkms_key::has_next_key()
{
  return !was_key_retrieved;	  
}

void Gkms_key::xor_data()
{
  /* We do not xor data in keyring_vault */
}

uchar* Gkms_key::get_key_data() const
{
  return key.get();
}

size_t Gkms_key::get_key_data_size() const
{
  return key_len;
}

const std::string* Gkms_key::get_key_type() const
{
  return &this->key_type;
}

void Gkms_key::create_key_signature() const
{
  if (key_id.empty())
    return;
  std::ostringstream key_signature_ss;
  key_signature_ss << key_id.length() << '_';
  key_signature_ss << key_id;
  key_signature_ss << user_id.length() << '_';
  key_signature_ss << user_id;
  key_signature = key_signature_ss.str();
}

} // namespace keyring
