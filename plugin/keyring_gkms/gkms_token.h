#ifndef SMART_LOOP_GKMS_TOKEN_H
#define SMART_LOOP_GKMS_TOKEN_H

#include "vault_secure_string.h"

namespace keyring {

struct Gkms_token
{
  Gkms_token()
    : token("")
    , expires_at_unixtimestamp(0)
  {}

  Gkms_token(Secure_string token,
             int expires_at_unixtimestamp)
    : token(token)
    , expires_at_unixtimestamp(expires_at_unixtimestamp)
  {}

  bool is_empty()
  {
    return token.empty();
  }

  Secure_string token;
  int expires_at_unixtimestamp;  
};

} // namespace keyring

#endif
