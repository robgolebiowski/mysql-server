#ifndef SMART_LOOP_GKMS_IO_H
#define SMART_LOOP_GKMS_IO_H

namespace keyring {

class Gkms_io : public IKeyring_io
{
public:
  Gkms_io(ILogger *logger)
  {}

  ~Gkms_io();

  virtual my_bool init(std::string *keyring_storage_url);
  virtual my_bool flush_to_backup(ISerialized_object *serialized_object)
  {
    return FALSE;
  }
  virtual my_bool flush_to_storage(ISerialized_object *serialized_object);

  virtual ISerializer *get_serializer();
  virtual my_bool get_serialized_object(ISerialized_object **serialized_object);
  virtual my_bool has_next_serialized_object()
  {
    return FALSE;
  }
};

}//namespace keyring

#endif //SMART_LOOP_GKMS_IO_H 
