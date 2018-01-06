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
#include "gkms_conf_parser.h"
#include "logger.h"
//#include <mysql/plugin_keyring.h>
//#include <sql_plugin_ref.h>
//#include "keyring_key.h"
//#include "buffered_file_io.h"

namespace keyring_gkms_conf_parser_unittest
{
  using namespace keyring;
  using ::testing::StrEq;

  class Gkms_conf_parser_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
      //keyring_file_data_key = PSI_NOT_INSTRUMENTED;
      //keyring_backup_file_data_key = PSI_NOT_INSTRUMENTED;
      logger= new Logger(logger);
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

  TEST_F(Gkms_conf_parser_test, Parse_conf_file)
  {
    std::string file_name("./conf_file");
    std::remove(file_name.c_str());
    std::ofstream conf_file(file_name.c_str());
    conf_file << R"("key1" : "value1")" << std::endl;
    conf_file << R"("key___22__" : "value___22__2")" << std::endl;
    conf_file << R"("123key1_continues" : "value_also continues")" << std::endl;
    conf_file.close();
    
    Gkms_conf_parser gkms_conf_parser;
    Gkms_conf_parser::ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file(file_name, conf_map), false);

    EXPECT_STREQ("value1", conf_map["key1"].c_str());
    EXPECT_STREQ("value___22__2", conf_map["key___22__"].c_str());
    EXPECT_STREQ("value_also continues", conf_map["123key1_continues"].c_str());
  }

  TEST_F(Gkms_conf_parser_test, Parse_empty_conf_file)
  {
    std::string file_name("./empty_conf_file");
    std::remove(file_name.c_str());
    std::ofstream conf_file(file_name.c_str());
    conf_file.close(); 
   
    Gkms_conf_parser gkms_conf_parser;
    Gkms_conf_parser::ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file(file_name, conf_map), false);
    EXPECT_TRUE(conf_map.size() == 0);
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
    
    Gkms_conf_parser gkms_conf_parser;
    Gkms_conf_parser::ConfMap conf_map;
    EXPECT_EQ(gkms_conf_parser.parse_file(file_name, conf_map), false);

    EXPECT_STREQ("robert@keyring-122511.iam.gserviceaccount.com", conf_map["iss"].c_str());
    EXPECT_STREQ("https://www.googleapis.com/auth/cloudkms", conf_map["scope"].c_str());
    EXPECT_STREQ("https://www.googleapis.com/oauth2/v4/token", conf_map["aud"].c_str());
    EXPECT_STREQ("/home/rob/very_secret/key", conf_map["private_key"].c_str());
  }
}
