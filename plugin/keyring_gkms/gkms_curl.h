#ifndef SMART_LOOP_GKMS_CURL_H
#define SMART_LOOP_GKMS_CURL_H

#include <my_global.h>
#include <curl/curl.h>

#include <string>
#include "keyring_memory.h"
#include "vault_memory.h"
#include "vault_secure_string.h"

#include "logger.h"

namespace keyring {

//template <class T> class Secure_allocator : public std::allocator<T>
  //{
  //public:

    //template<class U> struct rebind { typedef Secure_allocator<U> other; };
    //Secure_allocator() throw() {}
    //Secure_allocator(const Secure_allocator& secure_allocator) : std::allocator<T>(secure_allocator)
    //{}
    //template <class U> Secure_allocator(const Secure_allocator<U>&) throw() {}

    //T* allocate(size_t n)
    //{
      //if (n == 0)
        //return NULL;
      //else if (n > INT_MAX)
        //throw std::bad_alloc();
      //return keyring_malloc<T*>(n*sizeof(T)); 
    //}

    //void deallocate(T *p, size_t n)
    //{
      //memset_s(p, n, 0, n);
      //my_free(p);
    //}
  //};

//typedef std::basic_string<char, std::char_traits<char>, Secure_allocator<char> > Secure_string;
//typedef std::basic_ostringstream<char, std::char_traits<char>, Secure_allocator<char> > Secure_ostringstream;

class Gkms_curl
{
public:
  Gkms_curl(ILogger *logger)
    : curl(NULL) 
    , logger(logger)
    , list(NULL)
    , was_initialized(false)
  {}
  ~Gkms_curl()
  {
    if (curl != NULL)
      curl_easy_cleanup(curl);
    if (list != NULL)
      curl_slist_free_all(list);
  }

  bool init();
  bool set_url(const Secure_string &url)
  {
    return (curl_res = curl_easy_setopt(curl, CURLOPT_URL, url.c_str())) != CURLE_OK;
  }
  bool set_post_data(const Secure_string &post_data)
  {
    return (curl_res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str())) != CURLE_OK ||
           (curl_res = curl_easy_setopt(curl, CURLOPT_POST, 1)) != CURLE_OK;
  }
  //bool set_token(const Secure_string &token)
  //{
    //return (curl_res = curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str())) != CURLE_OK; 
  //}
  bool set_content_type(const Secure_string &content_type)
  {
    return (list = curl_slist_append(list, content_type.c_str())) == NULL;
  }
  bool set_content_length(uint content_length)
  {
    Secure_ostringstream oss;
    oss << "Content-Length: ";
    oss << content_length;
    Secure_string length(oss.str());
    return (list = curl_slist_append(list, length.c_str())) == NULL;
  }


  bool set_token(const Secure_string &token)
  {
    Secure_ostringstream oss;
    oss << "Authorization: Bearer ";
    oss << token;
    Secure_string auth_token(oss.str());
    return (list = curl_slist_append(list, auth_token.c_str())) == NULL;
  }

  Secure_string get_response()
  {
    return read_data_ss.str();
  }
  bool execute()
  {
    if (!was_initialized || curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list) != CURLE_OK)
      return true;
    CURLcode curl_res = curl_easy_perform(curl);
    curl_slist_free_all(list);
    list = NULL;
    return curl_res != CURLE_OK;
  }

private:
  //std::string get_error();

  CURL *curl;
  ILogger *logger;
  struct curl_slist *list;
  char curl_errbuf[CURL_ERROR_SIZE]; // error from CURL
  Secure_ostringstream read_data_ss;
  CURLcode curl_res; // status of the last curl call
  std::string get_error();
  bool was_initialized;
};


} //namespace keyring

#endif //SMART_LOOP_GKMS_CURL_H


