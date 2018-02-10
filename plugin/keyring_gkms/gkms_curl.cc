#include "gkms_curl.h"

static const size_t max_response_size = 32000000;

namespace keyring
{
  static size_t write_response_memory(void *contents, size_t size, size_t nmemb, void *userp)
  {
    size_t realsize = size * nmemb;
    if (size != 0 && realsize / size != nmemb)
      return 0; // overflow
    Secure_ostringstream *read_data = static_cast<Secure_ostringstream*>(userp);
    size_t ss_pos = read_data->tellp();
    read_data->seekp(0, std::ios::end);
    size_t number_of_read_bytes = read_data->tellp();
    read_data->seekp(ss_pos);

    if (number_of_read_bytes + realsize > max_response_size)
      return 0; // response size limit exceeded

    read_data->write(static_cast<char*>(contents), realsize);
    if (!read_data->good())
      return 0;
    return realsize;
  }

  bool Gkms_curl::init()
  {
    CURLcode curl_res = CURLE_OK;
    curl_errbuf[0] = '\0';

    //TODO: is gcloud ca needed here ?

    if ((curl = curl_easy_init()) == NULL ||
        //(list = curl_slist_append(list, token_header.c_str())) == NULL ||
        //(list = curl_slist_append(list, "Content-Type: application/json")) == NULL ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_memory)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(&read_data_ss))) != CURLE_OK ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L)) != CURLE_OK ||
        //(!vault_ca.empty() &&
         //(curl_res = curl_easy_setopt(curl, CURLOPT_CAINFO, vault_ca.c_str())) != CURLE_OK
        //) ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL)) != CURLE_OK //||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout)) != CURLE_OK ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback)) ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L))
       )
    {
      //TODO: This needs to be restored
      //logger->log(MY_ERROR_LEVEL, get_error_from_curl(curl_res).c_str());
      return true;
    }
    return false;
  }




  std::string Gkms_curl::get_error()
  {
    size_t len = strlen(curl_errbuf);
    std::ostringstream ss;
    if (curl_res != CURLE_OK)
    {
      ss << "CURL returned this error code: " << curl_res;
      ss << " with error message : ";
      if (len)
        ss << curl_errbuf;
      else
        ss << curl_easy_strerror(curl_res);
    }
    return ss.str();
  }

}
