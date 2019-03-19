#ifndef MYSQL_GKMS_KEY_H
#define MYSQL_GKMS_KEY_H

#include "keyring_key.h"
#include "i_serialized_object.h"

namespace keyring {

struct Gkms_key : public Key, public ISerialized_object
{
  Gkms_key(const char *a_key_id, const char *a_key_type, const char *a_user_id,
      const void *a_key, size_t a_key_len)
    : Key(a_key_id, a_key_type, a_user_id, a_key, a_key_len)
    , was_key_retrieved(false)	
  {}

  Gkms_key(const Gkms_key &gkms_key)
    : Key(gkms_key.key_id.c_str(), gkms_key.key_type.c_str(),
          gkms_key.user_id.c_str(), gkms_key.key.get(), gkms_key.key_len)
    , was_key_retrieved(false)
  {
    this->key_operation = gkms_key.key_operation;
  }
  Gkms_key()
  {}
 
  using Key::get_key_data;
  uchar* get_key_data() const;
  using Key::get_key_data_size;
  size_t get_key_data_size() const;
  using Key::get_key_type;
  const std::string* get_key_type() const;

  virtual my_bool get_next_key(IKey **key);
  virtual my_bool has_next_key();
  virtual void create_key_signature() const;
  virtual void xor_data();

protected:
  bool was_key_retrieved;
};

} // namespace keyring

#endif // MYSQL_GKMS_KEY_H
