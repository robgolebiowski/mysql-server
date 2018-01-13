#include "gkms_token.h"
#include "gkms_curl.h"
#include <time.h>

namespace keyring
{

bool Gkms_token::get_token(Secure_string &token)
{
  return true;
}

bool Gkms_token::generate_request_body()
{
  //if 
  time_t timer;
  time(&timer);
  return true;
}


} //namespace keyring
