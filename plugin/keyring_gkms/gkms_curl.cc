#include "gkms_curl.h"

static const size_t max_response_size = 32000000;

namespace keyring
{
//struct data {
  //char trace_ascii; //[> 1 or 0 <] 
//};
 
//static
//void dump(const char *text,
          //FILE *stream, unsigned char *ptr, size_t size,
          //char nohex)
//{
  //size_t i;
  //size_t c;
 
  //unsigned int width = 0x10;
 
  //if(nohex)
    ////[> without the hex output, we can fit more on screen <] 
    //width = 0x40;
 
  //fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n",
          //text, (long)size, (long)size);
 
  //for(i = 0; i<size; i += width) {
 
    //fprintf(stream, "%4.4lx: ", (long)i);
 
    //if(!nohex) {
      ////[> hex not disabled, show it <] 
      //for(c = 0; c < width; c++)
        //if(i + c < size)
          //fprintf(stream, "%02x ", ptr[i + c]);
        //else
          //fputs("   ", stream);
    //}
 
    //for(c = 0; (c < width) && (i + c < size); c++) {
      ////[> check for 0D0A; if found, skip past and start a new line of output <] 
      //if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         //ptr[i + c + 1] == 0x0A) {
        //i += (c + 2 - width);
        //break;
      //}
      //fprintf(stream, "%c",
              //(ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      ////[> check again for 0D0A, to avoid an extra \n if it's at width <] 
      //if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         //ptr[i + c + 2] == 0x0A) {
        //i += (c + 3 - width);
        //break;
      //}
    //}
    //fputc('\n', stream); //[> newline <] 
  //}
  //fflush(stream);
//}
 
//static
//int my_trace(CURL *handle, curl_infotype type,
             //char *data, size_t size,
             //void *userp)
//{
  //struct data *config = (struct data *)userp;
  //const char *text;
  //(void)handle; //[> prevent compiler warning <] 
 
  //switch(type) {
  //case CURLINFO_TEXT:
    //fprintf(stderr, "== Info: %s", data);
    ////[> FALLTHROUGH <] 
  //default: //[> in case a new one is introduced to shock us <] 
    //return 0;
 
  //case CURLINFO_HEADER_OUT:
    //text = "=> Send header";
    //break;
  //case CURLINFO_DATA_OUT:
    //text = "=> Send data";
    //break;
  //case CURLINFO_SSL_DATA_OUT:
    //text = "=> Send SSL data";
    //break;
  //case CURLINFO_HEADER_IN:
    //text = "<= Recv header";
    //break;
  //case CURLINFO_DATA_IN:
    //text = "<= Recv data";
    //break;
  //case CURLINFO_SSL_DATA_IN:
    //text = "<= Recv SSL data";
    //break;
  //}
  ////_IO_FILE * output = fopen("/home/rob/dump", "rw");
  //dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
  //return 0;
//}



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
     //struct data config;
 
  //config.trace_ascii = 1; [> enable ascii tracing <] 
    //TODO: is gcloud ca needed here ?

    if ((curl = curl_easy_init()) == NULL ||
        //(list = curl_slist_append(list, token_header.c_str())) == NULL ||
        //(list = curl_slist_append(list, "Content-Type: application/json")) == NULL ||
        //(list = curl_slist_append(list, "Content-Type: application/x-www-form-urlencoded")) == NULL ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_memory)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(&read_data_ss))) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true)) != CURLE_OK //||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace)) != CURLE_OK ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config)) != CURLE_OK


     
        //(curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1)) != CURLE_OK ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L)) != CURLE_OK ||
        //(!vault_ca.empty() &&
         //(curl_res = curl_easy_setopt(curl, CURLOPT_CAINFO, vault_ca.c_str())) != CURLE_OK
        //) ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL)) != CURLE_OK //||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout)) != CURLE_OK ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback)) ||
        //(curl_res = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L))
       )
    {
      //TODO: This needs to be restored
      //logger->log(MY_ERROR_LEVEL, get_error_from_curl(curl_res).c_str());
      was_initialized = false;
      return true;
    }
    was_initialized = true;
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
