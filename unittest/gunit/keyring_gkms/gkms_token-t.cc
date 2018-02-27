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
#include <gkms_token_receiver.h>
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

  class Gkms_token_receiver_testable : public Gkms_token_receiver
  {
  public:
    Gkms_token_receiver_testable(ILogger *logger, ConfMap &conf_map, const std::string &fake_request_body)
    : Gkms_token_receiver(logger, conf_map)
    , fake_request_body(fake_request_body)
    {}

    Gkms_token_receiver_testable(ILogger *logger, ConfMap &conf_map)
    : Gkms_token_receiver_testable(logger, conf_map, "")
    {}

    Secure_string get_encoded_header()
    {
      return Gkms_token_receiver::get_encoded_header();  
    }

    Secure_string get_encoded_body()
    {
      return Gkms_token_receiver::get_encoded_body();
    }

    // TODO: Change to Secure_string
    virtual std::string get_request_body()
    {
      return fake_request_body.empty() ? Gkms_token_receiver::get_request_body()
                                       : fake_request_body;
    }

    Secure_string get_sha256_request_dgst(const Secure_string &encoded_request)
    {
      return Gkms_token_receiver::get_sha256_request_dgst(encoded_request); 
    }

    static Secure_string get_token_from_response(const Secure_string &response)
    {
      return Gkms_token_receiver::get_token_from_reponse(response);
    }

    static int get_expires_in_from_reponse(const Secure_string &response)
    {
      return Gkms_token_receiver::get_expires_in_from_reponse(response);
    }

  private:
    const std::string &fake_request_body;
  };

  class Gkms_token_receiver_test : public ::testing::Test
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
      conf_file << R"("iss":"robert@keyring-182914.iam.gserviceaccount.com")" << std::endl;
      conf_file << R"("scope":"https://www.googleapis.com/auth/cloudkms")" << std::endl;
      conf_file << R"("aud":"https://www.googleapis.com/oauth2/v4/token")" << std::endl;
      conf_file << R"("private_key":"/home/rob/google_key/private_key")" << std::endl;
      conf_file << R"("bucket_name":keys-storage)" << std::endl;

      conf_file.close();
    }
  };

  TEST_F(Gkms_token_receiver_test, Generate_request_body)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file("./conf_file", conf_map), false);
    ILogger *mock_logger = new Mock_logger;
    Gkms_token_receiver_testable gkms_token_testable(mock_logger, conf_map);
    std::string request_body = gkms_token_testable.get_request_body();
    EXPECT_EQ(request_body.empty(), false);
    std::string expected_request_body(R"({"iss":"robert@keyring-122511.iam.gserviceaccount.com",)"
                                      R"("scope":"https://www.googleapis.com/auth/cloudkms",)"
                                      R"("aud":"https://www.googleapis.com/oauth2/v4/token",)"
                                      //R"("private_key":"/home/rob/very_secret/key",)"
                                      R"("iat":)");

    EXPECT_STREQ(request_body.substr(0, expected_request_body.length()).c_str(), expected_request_body.c_str());
    std::chrono::duration<int> seconds_timestamp = std::chrono::seconds(std::time(NULL));
    int unix_timestamp = seconds_timestamp.count();
    int iat_timestamp = std::stoul(request_body.substr(expected_request_body.length(), 10)); 
    ASSERT_TRUE(iat_timestamp <= unix_timestamp && unix_timestamp <= iat_timestamp + 200); 

    int exp_timestamp = std::stoul(request_body.substr(expected_request_body.length() + 10 + strnlen(R"(,"iat":)", 10))); 

    ASSERT_TRUE(exp_timestamp <= unix_timestamp + 3600 && unix_timestamp + 3600 <= exp_timestamp + 200); 
  }

  TEST_F(Gkms_token_receiver_test, Get_encoded_header)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file("./conf_file", conf_map), false);
    ILogger *mock_logger = new Mock_logger;
    Gkms_token_receiver_testable gkms_token_testable(mock_logger, conf_map);
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

  TEST_F(Gkms_token_receiver_test, Get_encoded_body)
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
    ILogger *mock_logger = new Mock_logger;
    Gkms_token_receiver_testable gkms_token_testable(mock_logger, conf_map, fake_request_body);
    EXPECT_STREQ(gkms_token_testable.get_encoded_body().c_str(), "ewoiaXNzIjoicm9iZXJ0QGtleXJpbmctMTgyOTE0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKInNjb3BlIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vYXV0aC9jbG91ZGttcyIsCiJhdWQiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjQvdG9rZW4iLAoiZXhwIjoxNTE1ODQwNTc0LAoiaWF0IjoxNTE1ODM2OTYzCn0K");
  }

  TEST_F(Gkms_token_receiver_test, Get_body_digest)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    generate_correct_conf_file();
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
    ILogger *mock_logger = new Mock_logger;
    Gkms_token_receiver_testable gkms_token_testable(mock_logger, conf_map, fake_request_body);
    Secure_string dgst = gkms_token_testable.get_sha256_request_dgst(gkms_token_testable.get_encoded_header() + '.' +
                                                                     gkms_token_testable.get_encoded_body());
    //EXPECT_STREQ(dgst.c_str(), "4e242979aa7a911fe92f6804a0db1cd1d212d05699dcf37fc6334749d4854f1d");
    EXPECT_STREQ(dgst.c_str(), "blVX2yv7HMw_oKfi2HZh7diSj7QK5OyY826gQ2mSDcrewSKIX6WiVmUCNX38CjdhxAqDUp7WNKnqGN_Qf6wiCtC_DM_FT-Pde157yjMEMrJQUodU5O7dZYA7pVm8BOXBYRuaT31Q1IWxleGAUVxKbZmLXfA6qDmyEJHLmxOdJb29_ilHaIEO5CMbIyAfVkwKk1M_Y_Q3JCbebM30V3qxsibXVhs9plz2g9lItu85M-LViQj8wAaqlda3h7QDEFIKA-WrTQNCLrgcycquXL8fmuA_epL2INqpyvEBTxmK8OqPypx5WeVNuSWy9gYrrK-_QxfhHAafXpTla4waF7_mqA");
  }

  TEST_F(Gkms_token_receiver_test, Get_token)
  {
    Gkms_conf_parser gkms_conf_parser(logger);
    generate_correct_conf_file();
    ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file("./conf_file", conf_map), false);
    ILogger *mock_logger = new Mock_logger;
    Gkms_token_receiver gkms_token(mock_logger, conf_map);
    Secure_string token = gkms_token.get_token().token;
    //EXPECT_STREQ(dgst.c_str(), "4e242979aa7a911fe92f6804a0db1cd1d212d05699dcf37fc6334749d4854f1d");
    EXPECT_STREQ(token.c_str(), "blVX2yv7HMw_oKfi2HZh7diSj7QK5OyY826gQ2mSDcrewSKIX6WiVmUCNX38CjdhxAqDUp7WNKnqGN_Qf6wiCtC_DM_FT-Pde157yjMEMrJQUodU5O7dZYA7pVm8BOXBYRuaT31Q1IWxleGAUVxKbZmLXfA6qDmyEJHLmxOdJb29_ilHaIEO5CMbIyAfVkwKk1M_Y_Q3JCbebM30V3qxsibXVhs9plz2g9lItu85M-LViQj8wAaqlda3h7QDEFIKA-WrTQNCLrgcycquXL8fmuA_epL2INqpyvEBTxmK8OqPypx5WeVNuSWy9gYrrK-_QxfhHAafXpTla4waF7_mqA");
  }

  TEST_F(Gkms_token_receiver_test, Get_token_from_response)
  {
    Secure_string token = Gkms_token_receiver_testable::get_token_from_response(
    R"("access_token": "ya29.c.ElphBfLPZqr8ForR2r53IaIV6P9WYMKSi-8SE3Oyfs159fmAYwsEou2B0q8iUbb6vT_m-QEExRWTpoDAClmDY_Y0cciHeSmFQmBJcQ6Tl8Tvd0K1Skof8kkOKkI",)"
    R"("token_type": "Bearer",)"
    R"("expires_in": 3600)");

    EXPECT_STREQ(token.c_str(), "ya29.c.ElphBfLPZqr8ForR2r53IaIV6P9WYMKSi-8SE3Oyfs159fmAYwsEou2B0q8iUbb6vT_m-QEExRWTpoDAClmDY_Y0cciHeSmFQmBJcQ6Tl8Tvd0K1Skof8kkOKkI");
  }

  TEST_F(Gkms_token_receiver_test, Get_expires_in_from_response)
  {
    int expires_in = Gkms_token_receiver_testable::get_expires_in_from_reponse(
    R"("{access_token": "ya29.c.ElphBfLPZqr8ForR2r53IaIV6P9WYMKSi-8SE3Oyfs159fmAYwsEou2B0q8iUbb6vT_m-QEExRWTpoDAClmDY_Y0cciHeSmFQmBJcQ6Tl8Tvd0K1Skof8kkOKkI",)"
    R"("token_type": "Bearer",)"
    R"("expires_in": 3600})");

    EXPECT_EQ(expires_in, 3600);
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
