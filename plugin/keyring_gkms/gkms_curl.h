#ifndef SMART_LOOP_GKMS_CURL_H
#define SMART_LOOP_GKMS_CURL_H

#include <my_global.h>
#include <curl/curl.h>

namespace keyring {

typedef std::basic_string<char, std::char_traits<char>, Secure_allocator<char> > Secure_string;
typedef std::basic_ostringstream<char, std::char_traits<char>, Secure_allocator<char> > Secure_ostringstream;

class Gkms_curl
{
  Gkms_curl(ILogger *logger)
    : curl(NULL) 
    , logger(logger)
    , list(NULL)
  {}
  ~Gkms_curl()
  {
    if (curl != NULL)
      curl_easy_cleanup(curl);
    if (list != NULL)
      curl_slist_free_all(list);
  }

  bool init();
  bool set_url(std::string &url)
  {
    return (curl_res = curl_easy_setopt(curl, CURLOPT_URL, url.c_str())) != CURLE_OK;
  }
  bool set_post_request(std::string &post_request)
  {
    return (curl_res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_request.c_str())) != CURLE_OK;
  }

private:
  CURL *curl;
  ILogger *logger;
  struct curl_slist *list;
  char curl_errbuf[CURL_ERROR_SIZE]; // error from CURL
  Secure_ostringstream read_data_ss;
  CURLcode curl_res; // status of the last curl call
  std::string get_error();
};


} //namespace keyring

#endif //SMART_LOOP_GKMS_CURL_H


