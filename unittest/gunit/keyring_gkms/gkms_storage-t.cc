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
//#include "gkms_conf_parser.h"
#include "mock_logger.h"
#include "gkms_storage.h"
#include "keyring_key.h"
#include "gkms_conf_map.h"
//#include <mysql/plugin_keyring.h>
//#include <sql_plugin_ref.h>
//#include "keyring_key.h"
//#include "buffered_file_io.h"

namespace keyring_gkms_storage_unittest
{
  using namespace keyring;
  using ::testing::StrEq;

  class Gkms_storage_test : public ::testing::Test
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
  };

  TEST_F(Gkms_storage_test, Simple_upload)
  {
    ConfMap conf_map;
    conf_map["iss"] = "robert@keyring-182914.iam.gserviceaccount.com";
    //https://www.googleapis.com/auth/devstorage.read_write
    //conf_map["scope"] = "https://www.googleapis.com/auth/cloudkms";
    conf_map["scope"] = "https://www.googleapis.com/auth/devstorage.read_write";
    conf_map["aud"] = "https://www.googleapis.com/oauth2/v4/token";
    conf_map["private_key"] = "/home/rob/google_key/private_key";
    conf_map["bucket_name"] = "keys-storage";

    std::string sample_key_data("roberts_key");
    Key key_to_add("Robert_add_key", "AES", "Roberts_add_key_type", sample_key_data.c_str(), sample_key_data.length()+1);

//bool Gkms_storage::write_key(IKey *key)
    Gkms_storage storage;
    storage.init(logger);
    storage.set_conf_map(conf_map); 
    EXPECT_FALSE(storage.write_key(&key_to_add));

    //std::string file_name("./conf_file");
    //std::remove(file_name.c_str());
    //std::ofstream conf_file(file_name.c_str());
    //conf_file << R"("key1" : "value1")" << std::endl;
    //conf_file << R"("key___22__" : "value___22__2")" << std::endl;
    //conf_file << R"("123key1_continues" : "value_also continues")" << std::endl;
    //conf_file.close();
    
    //EXPECT_CALL(*((Mock_logger *)logger),
                //log(MY_ERROR_LEVEL, StrEq("Unknown field in configuration file: key1")));
    //Gkms_conf_parser gkms_conf_parser(logger);
    //ConfMap conf_map;
    //EXPECT_EQ(gkms_conf_parser.parse_file(file_name.c_str(), conf_map), true);

    //EXPECT_TRUE(conf_map["iss"].empty());
    //EXPECT_TRUE(conf_map["scope"].empty());
    //EXPECT_TRUE(conf_map["aud"].empty());
    //EXPECT_TRUE(conf_map["private_key"].empty());
    //EXPECT_TRUE(conf_map.count("key1") == 0);
    //EXPECT_TRUE(conf_map.count("key___22__") == 0);
    //EXPECT_TRUE(conf_map.count("123key1_continues") == 0);
    //EXPECT_STREQ("value___22__2", conf_map["key___22__"].c_str());
    //EXPECT_STREQ("value_also continues", conf_map["123key1_continues"].c_str());
  }

  //TEST_F(Gkms_conf_parser_test, Parse_empty_conf_file)
  //{
    //std::string file_name("./empty_conf_file");
    //std::remove(file_name.c_str());
    //std::ofstream conf_file(file_name.c_str());
    //conf_file.close(); 
   
    //Gkms_conf_parser gkms_conf_parser(logger);
    //ConfMap conf_map;
    //EXPECT_CALL(*((Mock_logger *)logger),
                //log(MY_ERROR_LEVEL, StrEq("Configuration file does not contain field: aud")));
    //EXPECT_EQ(gkms_conf_parser.parse_file(file_name.c_str(), conf_map), true);
    //EXPECT_TRUE(conf_map["iss"].empty());
    //EXPECT_TRUE(conf_map["scope"].empty());
    //EXPECT_TRUE(conf_map["aud"].empty());
    //EXPECT_TRUE(conf_map["private_key"].empty());
  //}

  //TEST_F(Gkms_conf_parser_test, Parse_conf_file_with_missing_private_key)
  //{
    //std::string file_name("./conf_file");
    //std::remove(file_name.c_str());
    //std::ofstream conf_file(file_name.c_str());
    //conf_file << R"("iss":"robert@keyring-122511.iam.gserviceaccount.com")" << std::endl;
    //conf_file << R"("scope":"https://www.googleapis.com/auth/cloudkms")" << std::endl;
    //conf_file << R"("aud":"https://www.googleapis.com/oauth2/v4/token")" << std::endl;
    //conf_file << R"("bucket_name":"keys-storage")" << std::endl;
    //conf_file.close();
    
    //Gkms_conf_parser gkms_conf_parser(logger);
    //ConfMap conf_map;
    //EXPECT_CALL(*((Mock_logger *)logger),
                //log(MY_ERROR_LEVEL, StrEq("Configuration file does not contain field: private_key")));
    //EXPECT_EQ(gkms_conf_parser.parse_file(file_name.c_str(), conf_map), true);

    //EXPECT_TRUE(conf_map.size() == 5);
    //EXPECT_STREQ("robert@keyring-122511.iam.gserviceaccount.com", conf_map["iss"].c_str());
    //EXPECT_STREQ("https://www.googleapis.com/auth/cloudkms", conf_map["scope"].c_str());
    //EXPECT_STREQ("https://www.googleapis.com/oauth2/v4/token", conf_map["aud"].c_str());
    //EXPECT_STREQ("keys-storage", conf_map["bucket_name"].c_str());
    //EXPECT_TRUE(conf_map["private_key"].empty());
  //}


  //TEST_F(Gkms_conf_parser_test, Parse_conf_file_with_correct_conf)
  //{
    //std::string file_name("./conf_file");
    //std::remove(file_name.c_str());
    //std::ofstream conf_file(file_name.c_str());
    //conf_file << R"("iss":"robert@keyring-122511.iam.gserviceaccount.com")" << std::endl;
    //conf_file << R"("scope":"https://www.googleapis.com/auth/cloudkms")" << std::endl;
    //conf_file << R"("aud":"https://www.googleapis.com/oauth2/v4/token")" << std::endl;
    //conf_file << R"("private_key":"/home/rob/very_secret/key")" << std::endl;
    //conf_file << R"("bucket_name":"keys-storage")" << std::endl;
    //conf_file.close();
    
    //Gkms_conf_parser gkms_conf_parser(logger);
    //ConfMap conf_map;
    //EXPECT_EQ(gkms_conf_parser.parse_file(file_name.c_str(), conf_map), false);

    //EXPECT_STREQ("robert@keyring-122511.iam.gserviceaccount.com", conf_map["iss"].c_str());
    //EXPECT_STREQ("https://www.googleapis.com/auth/cloudkms", conf_map["scope"].c_str());
    //EXPECT_STREQ("https://www.googleapis.com/oauth2/v4/token", conf_map["aud"].c_str());
    //EXPECT_STREQ("/home/rob/very_secret/key", conf_map["private_key"].c_str());
    //EXPECT_STREQ("keys-storage", conf_map["bucket_name"].c_str());
  //}
}
