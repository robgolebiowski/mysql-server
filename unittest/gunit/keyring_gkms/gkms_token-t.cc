/* Copyright (c) 2016, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <my_global.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <gkms_token.h>
//#include "gkms_conf_parser.h"
#include "mock_logger.h"
#include <chrono>
//#include <mysql/plugin_keyring.h>
//#include <sql_plugin_ref.h>
//#include "keyring_key.h"
//#include "buffered_file_io.h"

//#if !defined(MERGE_UNITTESTS)
#ifdef HAVE_PSI_INTERFACE
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
  //PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
//#endif
//mysql_rwlock_t LOCK_keyring;
#endif

namespace keyring_gkms_token_unittest
{
  using namespace keyring;
  using ::testing::StrEq;

  class Gkms_token_testable : public Gkms_token
  {
  public:
    Gkms_token_testable(ConfMap &conf_map, const std::string &fake_request_body)
    : Gkms_token(conf_map)
    , fake_request_body(fake_request_body)
    {}

    Gkms_token_testable(ConfMap &conf_map)
    : Gkms_token_testable(conf_map, "")
    {}

    Secure_string get_encoded_header()
    {
      return Gkms_token::get_encoded_header();  
    }

    Secure_string get_encoded_body()
    {
      return Gkms_token::get_encoded_body();
    }

    // TODO: Change to Secure_string
    virtual std::string get_request_body()
    {
      return fake_request_body.empty() ? Gkms_token::get_request_body()
                                       : fake_request_body;
    }

  private:
    const std::string &fake_request_body;
  };

  class Gkms_token_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
      //keyring_file_data_key = PSI_NOT_INSTRUMENTED;
      //keyring_backup_file_data_key = PSI_NOT_INSTRUMENTED;
      logger= new Mock_logger;
    }

    virtual void TearDown()
    {
      //fake_mysql_plugin.name.str= const_cast<char*>("FakeKeyringPlugin");
      //fake_mysql_plugin.name.length= strlen("FakeKeyringPlugin");
      delete logger;
    }

  protected:
    //st_plugin_int fake_mysql_plugin;
    ILogger *logger;
    std::string fake_request_body;

    void generate_correct_conf_file()
    {
      std::string file_name("./conf_file");
      std::remove(file_name.c_str());
      std::ofstream conf_file(file_name.c_str());
      conf_file << R"("iss":"robert@keyring-122511.iam.gserviceaccount.com")" << std::endl;
      conf_file << R"("scope":"https://www.googleapis.com/auth/cloudkms")" << std::endl;
      conf_file << R"("aud":"https://www.googleapis.com/oauth2/v4/token")" << std::endl;
      conf_file << R"("private_key":"/home/rob/very_secret/key")" << std::endl;
      conf_file.close();
    }
  };

  TEST_F(Gkms_token_test, Generate_request_body)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file("./conf_file", conf_map), false);
    Gkms_token_testable gkms_token_testable(conf_map);
    std::string request_body = gkms_token_testable.get_request_body();
    EXPECT_EQ(request_body.empty(), false);
    std::string expected_request_body(R"({"iss":"robert@keyring-122511.iam.gserviceaccount.com",)"
                                      R"("scope":"https://www.googleapis.com/auth/cloudkms",)"
                                      R"("aud":"https://www.googleapis.com/oauth2/v4/token",)"
                                      R"("private_key":"/home/rob/very_secret/key",)"
                                      R"("iat":)");

    EXPECT_STREQ(request_body.substr(0, expected_request_body.length()).c_str(), expected_request_body.c_str());
    auto unix_timestamp = std::chrono::seconds(std::time(NULL)).count();
    uint iat_timestamp = std::stoul(request_body.substr(expected_request_body.length(), 10)); 
    ASSERT_TRUE(iat_timestamp <= unix_timestamp && unix_timestamp <= iat_timestamp + 200); 

    uint exp_timestamp = std::stoul(request_body.substr(expected_request_body.length() + 10 + strnlen(R"(,"iat":)", 10))); 

    ASSERT_TRUE(exp_timestamp <= unix_timestamp + 3600 && unix_timestamp + 3600 <= exp_timestamp + 200); 
  }

  TEST_F(Gkms_token_test, Get_encoded_header)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file("./conf_file", conf_map), false);
    Gkms_token_testable gkms_token_testable(conf_map);
    std::string request_body = gkms_token_testable.get_request_body();
    EXPECT_STREQ(gkms_token_testable.get_encoded_header().c_str(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");

 

    //EXPECT_EQ(request_body.empty(), false);
    //std::string expected_request_body(R"({"iss":"robert@keyring-122511.iam.gserviceaccount.com",)"
                                      //R"("scope":"https://www.googleapis.com/auth/cloudkms",)"
                                      //R"("aud":"https://www.googleapis.com/oauth2/v4/token",)"
                                      //R"("private_key":"/home/rob/very_secret/key",)"
                                      //R"("iat":)");

    //EXPECT_STREQ(request_body.substr(0, expected_request_body.length()).c_str(), expected_request_body.c_str());
    //auto unix_timestamp = std::chrono::seconds(std::time(NULL)).count();
    //uint iat_timestamp = std::stoul(request_body.substr(expected_request_body.length(), 10)); 
    //ASSERT_TRUE(iat_timestamp <= unix_timestamp && unix_timestamp <= iat_timestamp + 200); 

    //uint exp_timestamp = std::stoul(request_body.substr(expected_request_body.length() + 10 + strnlen(R"(,"iat":)", 10))); 

    //ASSERT_TRUE(exp_timestamp <= unix_timestamp + 3600 && unix_timestamp + 3600 <= exp_timestamp + 200); 
  }

  TEST_F(Gkms_token_test, Get_encoded_body)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file("./conf_file", conf_map), false);
    std::ostringstream fake_request_body_ss;
    fake_request_body_ss << R"({)" << std::endl;
    fake_request_body_ss << R"("iss":"robert@keyring-182914.iam.gserviceaccount.com",)" << std::endl;
    fake_request_body_ss << R"("scope":"https://www.googleapis.com/auth/cloudkms",)" << std::endl;
    fake_request_body_ss << R"("aud":"https://www.googleapis.com/oauth2/v4/token",)" << std::endl;
    fake_request_body_ss << R"("exp":1515840574,)" << std::endl;
    fake_request_body_ss << R"("iat":1515836963)" << std::endl;
    fake_request_body_ss << R"(})" << std::endl;
    std::string fake_request_body = fake_request_body_ss.str();
    Gkms_token_testable gkms_token_testable(conf_map, fake_request_body);
    EXPECT_STREQ(gkms_token_testable.get_encoded_body().c_str(), "ewoiaXNzIjoicm9iZXJ0QGtleXJpbmctMTgyOTE0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKInNjb3BlIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vYXV0aC9jbG91ZGttcyIsCiJhdWQiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjQvdG9rZW4iLAoiZXhwIjoxNTE1ODQwNTc0LAoiaWF0IjoxNTE1ODM2OTYzCn0K");

 

    //EXPECT_EQ(request_body.empty(), false);
    //std::string expected_request_body(R"({"iss":"robert@keyring-122511.iam.gserviceaccount.com",)"
                                      //R"("scope":"https://www.googleapis.com/auth/cloudkms",)"
                                      //R"("aud":"https://www.googleapis.com/oauth2/v4/token",)"
                                      //R"("private_key":"/home/rob/very_secret/key",)"
                                      //R"("iat":)");

    //EXPECT_STREQ(request_body.substr(0, expected_request_body.length()).c_str(), expected_request_body.c_str());
    //auto unix_timestamp = std::chrono::seconds(std::time(NULL)).count();
    //uint iat_timestamp = std::stoul(request_body.substr(expected_request_body.length(), 10)); 
    //ASSERT_TRUE(iat_timestamp <= unix_timestamp && unix_timestamp <= iat_timestamp + 200); 

    //uint exp_timestamp = std::stoul(request_body.substr(expected_request_body.length() + 10 + strnlen(R"(,"iat":)", 10))); 

    //ASSERT_TRUE(exp_timestamp <= unix_timestamp + 3600 && unix_timestamp + 3600 <= exp_timestamp + 200); 
  }

/*
  TEST_F(Gkms_conf_parser_test, Parse_empty_conf_file)
  {
    std::string file_name("./empty_conf_file");
    std::remove(file_name.c_str());
    std::ofstream conf_file(file_name.c_str());
    conf_file.close(); 
   
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_CALL(*((Mock_logger *)logger),
                log(MY_ERROR_LEVEL, StrEq("Configuration file does not contain field: aud")));
    EXPECT_EQ(gkms_conf_parser.parse_file(file_name, conf_map), true);
    EXPECT_TRUE(conf_map["iss"].empty());
    EXPECT_TRUE(conf_map["scope"].empty());
    EXPECT_TRUE(conf_map["aud"].empty());
    EXPECT_TRUE(conf_map["private_key"].empty());
  }

  TEST_F(Gkms_conf_parser_test, Parse_conf_file_with_missing_private_key)
  {
    std::string file_name("./conf_file");
    std::remove(file_name.c_str());
    std::ofstream conf_file(file_name.c_str());
    conf_file << R"("iss":"robert@keyring-122511.iam.gserviceaccount.com")" << std::endl;
    conf_file << R"("scope":"https://www.googleapis.com/auth/cloudkms")" << std::endl;
    conf_file << R"("aud":"https://www.googleapis.com/oauth2/v4/token")" << std::endl;
    conf_file.close();
    
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_CALL(*((Mock_logger *)logger),
                log(MY_ERROR_LEVEL, StrEq("Configuration file does not contain field: private_key")));
    EXPECT_EQ(gkms_conf_parser.parse_file(file_name, conf_map), true);

    EXPECT_TRUE(conf_map.size() == 4);
    EXPECT_STREQ("robert@keyring-122511.iam.gserviceaccount.com", conf_map["iss"].c_str());
    EXPECT_STREQ("https://www.googleapis.com/auth/cloudkms", conf_map["scope"].c_str());
    EXPECT_STREQ("https://www.googleapis.com/oauth2/v4/token", conf_map["aud"].c_str());
    EXPECT_TRUE(conf_map["private_key"].empty());
  }


  TEST_F(Gkms_conf_parser_test, Parse_conf_file_with_correct_conf)
  {
    std::string file_name("./conf_file");
    std::remove(file_name.c_str());
    std::ofstream conf_file(file_name.c_str());
    conf_file << R"("iss":"robert@keyring-122511.iam.gserviceaccount.com")" << std::endl;
    conf_file << R"("scope":"https://www.googleapis.com/auth/cloudkms")" << std::endl;
    conf_file << R"("aud":"https://www.googleapis.com/oauth2/v4/token")" << std::endl;
    conf_file << R"("private_key":"/home/rob/very_secret/key")" << std::endl;
    conf_file.close();
    
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file(file_name, conf_map), false);

    EXPECT_STREQ("robert@keyring-122511.iam.gserviceaccount.com", conf_map["iss"].c_str());
    EXPECT_STREQ("https://www.googleapis.com/auth/cloudkms", conf_map["scope"].c_str());
    EXPECT_STREQ("https://www.googleapis.com/oauth2/v4/token", conf_map["aud"].c_str());
    EXPECT_STREQ("/home/rob/very_secret/key", conf_map["private_key"].c_str());
  }*/
}
