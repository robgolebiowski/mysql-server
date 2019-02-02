#include "gkms_token_receiver.h"
#include "gkms_curl.h"
#include "gkms_response_parser.h"
#include <time.h>
#include <chrono>
#include "vault_base64.h"
#include "sha2.h"
#include "my_md5.h"                  // array_to_hex
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
//#include "file_io.h"
#include <stdio.h>
#include <string>


namespace keyring
{
// on error returns empty Gkms_token
Gkms_token Gkms_token_receiver::get_token()
{
  Gkms_token token; // empty token
  Gkms_curl curl(logger);
  if (curl.init())
    return token;
  curl.set_url(conf_map["aud"].c_str());
  Secure_string encoded_header = get_encoded_header(); 
  Secure_string encoded_body = get_encoded_body();
  if (encoded_header.empty() || encoded_body.empty())
    return token;
  Secure_string encoded_request = encoded_header + '.' + encoded_body;
  Secure_string encoded_request_dgst = get_sha256_request_dgst(encoded_request);
  if (encoded_request_dgst.empty())
    return token;
  Secure_ostringstream oss;
  oss << "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
  //oss << "/token?grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=";
  oss << encoded_request << '.' << encoded_request_dgst;
  Secure_string post_data = oss.str();
  curl.set_post_data(post_data);
  if (curl.execute())
  {
    //TODO: Add logger 
    return token;
  }
  Secure_string response = curl.get_response();
  token.token = Gkms_token_receiver::get_token_from_reponse(response);
  
  return token;
}

// TODO: Change to response, not reponse
Secure_string Gkms_token_receiver::get_token_from_reponse(const Secure_string &response)
{
  return Gkms_reponse_parser::get_value_from_reponse("access_token", response);
}

int Gkms_token_receiver::get_expires_in_from_reponse(const Secure_string &response)
{
  Secure_string expires_in = Gkms_reponse_parser::get_value_from_reponse("expires_in", response);
  int expires_in_digit = 0;
  try 
  {
    expires_in_digit = std::stoi(expires_in.c_str());
  }
  catch (const std::invalid_argument &e)
  {
    // TODO: Add logging
    expires_in_digit = 0;
  }
  catch (const std::out_of_range &e)
  {
    // TODO: Add logging
    expires_in_digit = 0;
  }
  return expires_in_digit;
}

std::string Gkms_token_receiver::get_request_body()
{
  std::ostringstream request_body_ss;
  request_body_ss << "{";
  request_body_ss << R"("iss":")" << conf_map["iss"] << R"(",)";
  request_body_ss << R"("scope":")" << conf_map["scope"] << R"(",)";
  request_body_ss << R"("aud":")" << conf_map["aud"] << R"(",)";
  auto unix_timestamp = std::chrono::seconds(std::time(NULL));
  request_body_ss << R"("iat":)" << unix_timestamp.count() << R"(,)";
  request_body_ss << R"("exp":)" << unix_timestamp.count() + 3600; //TODO: exp time is one hour in the future - should it be configurable ?
  //request_body_ss << R"("iat":)" << 1518360326 << R"(,)";
  //request_body_ss << R"("exp":)" << 1518363990; //TODO: exp time is one hour in the future - should it be configurable ?
  request_body_ss << "}" << std::endl;

  return request_body_ss.str();
}

Secure_string Gkms_token_receiver::get_encoded_header()
{
  //bool Vault_base64::encode(const void *src, size_t src_len, Secure_string *encoded, Base64Format format)
  Secure_string encoded_header;
  if (Vault_base64::encode(request_header.c_str(), request_header.length(), &encoded_header, Vault_base64::SINGLE_LINE))
  {
    // TODO: Add logger
    return "";
  }
  return encoded_header;
}

Secure_string Gkms_token_receiver::get_encoded_body()
{
  Secure_string encoded_body;
  std::string request_body = get_request_body();
  if (Vault_base64::encode(request_body.c_str(), request_body.length(), &encoded_body, Vault_base64::SINGLE_LINE))
  {
    //TODO: Add logger
    return ""; 
  }
  return encoded_body;
}

//Secure_string Gkms_token_receiver::get_sha256_request_dgst()
//{
  //Secure_string encoded_request = get_encoded_header() + '.' + get_encoded_body();
  //unsigned char digest_buf[256];
  //SHA256((const uchar*)encoded_request.c_str(), encoded_request.length(), (uchar*)digest_buf);

  //std::stringstream ss; // TODO: Change to secure one

  //for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    //ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest_buf[i];
  //return ss.str().c_str();
//}


Secure_string Gkms_token_receiver::get_sha256_request_dgst(const Secure_string &encoded_request)
{
  EVP_MD_CTX *mdctx = NULL;
   
  uchar *sig = NULL;

  _IO_FILE *pem_key_file = fopen(conf_map["private_key"].c_str(),"r");

  if (pem_key_file == NULL)
  {
    std::ostringstream oss;
    oss << "Could not open file with private key: ";
    oss << conf_map["private_key"];
    logger->log(MY_ERROR_LEVEL, oss.str().c_str());
    return "";
  }

  //File_io file_io(logger);
  //File pem_key_file= file_io.open(PSI_NOT_INSTRUMENTED, conf_map["private_key"].c_str(), // Change to some instrumentation
                                  //O_RDONLY, MYF(0));

  EVP_PKEY *privkey = EVP_PKEY_new();
  PEM_read_PrivateKey(pem_key_file, &privkey, NULL, NULL);

  /* Create the Message Digest Context */
  if(!(mdctx = EVP_MD_CTX_create()))
    return "";
   
  /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
   if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privkey))
     return "";
   
   /* Call update with the message */
   if(1 != EVP_DigestSignUpdate(mdctx, encoded_request.c_str(), encoded_request.length()))
     return "";
   
   /* Finalise the DigestSign operation */
   /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
    * signature. Length is returned in slen */
   size_t slen = 0;
   if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen))
     return "";
   /* Allocate memory for the signature based on size in slen */
   if(!(sig = (uchar*)OPENSSL_malloc(sizeof(unsigned char) * (slen))))
     return "";
   /* Obtain the signature */
   if(1 != EVP_DigestSignFinal(mdctx, sig, &slen))
     return "";

   //Secure_ostringstream ss;  
   Secure_string encoded_dgst;
   //std::string request_body = get_request_body();
   if (Vault_base64::encode(sig, slen, &encoded_dgst, Vault_base64::SINGLE_LINE))
   {
     //TODO: Add logger
     return ""; 
   }
  //return encoded_body;

   //for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
     //ss << std::hex << std::setw(2) << std::setfill('0') << (int)sig[i];

   /* Clean up */
   if(*sig) OPENSSL_free(sig);
   if(mdctx) EVP_MD_CTX_destroy(mdctx);

   //return ss.str().c_str();
   return encoded_dgst;

}

} //namespace keyring
