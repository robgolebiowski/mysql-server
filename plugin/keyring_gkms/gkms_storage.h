#ifndef SMART_LOOP_GKMS_STORAGE_H
#define SMART_LOOP_GKMS_STORAGE_H

#include "logger.h"
#include "i_keyring_key.h"
#include "gkms_conf_map.h"

namespace keyring {

class Gkms_storage
{
public:
  bool init(ILogger *logger)
  {
    this->logger = logger;
    return false;
  }

  bool set_conf_map(ConfMap &conf_map)
  {
    this->conf_map = conf_map;
    return false;
  }

  bool write_key(IKey *key);

protected:
  ILogger *logger;
  ConfMap conf_map;
};


} // namespace keyring

#endif // SMART_LOOP_GKMS_STORAGE_H
