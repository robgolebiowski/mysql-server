#ifndef SMART_LOOP_GKMS_CONF_PARSER_H
#define SMART_LOOP_GKMS_CONF_PARSER_H

#include "my_config.h"
//#include <boost/tokenizer.hpp>
//#include <boost/algorithm/string/erase.hpp>
#include <fstream>
#include "logger.h"
#include "gkms_conf_map.h"

namespace keyring {

//class ConfMap
//{
//public:
  //ConfMap(ILogger *logger)
    //: logger(logger)
  //{}

  //bool validate()
  //{
    //for (const auto& elem : conf_map)
    //{
      //if (elem.second.empty())
      //{
        //logger->log( 
      //}
    //}
  //}
//private:
  //ILogger *logger;
  //std::map<std::string, std::string> conf_map {{"iss",""}, {"scope",""}, {"aud",""}, {"private_key",""}};
//};




class Gkms_conf_parser
{
public:

  Gkms_conf_parser(ILogger *logger)
    : logger(logger)
  {}

  //bool parse_file(std::string &conf_file_path, ConfMap &conf_map)
  bool parse_file(const char *conf_file_path, ConfMap &conf_map)
  {
    fill_conf_map_with_required_keys(conf_map);

    std::ifstream fs;
    fs.open(conf_file_path, std::fstream::in);
    std::string line, key, value;
    while(std::getline(fs, line))
    {
      parse_line(line, key, value);
      if (conf_map.count(key) == 0)
      {
        std::string err_msg("Unknown field in configuration file: ");
        err_msg += key;
        logger->log(MY_ERROR_LEVEL, err_msg.c_str());
        return true;
      }
      conf_map[key] = value;
    }
    return check_if_all_required_keys_are_present(conf_map);
  }
protected:
  ILogger *logger;

  void fill_conf_map_with_required_keys(ConfMap &conf_map)
  {
    conf_map = {{"iss",""}, {"scope",""}, {"aud",""}, {"private_key",""}, {"bucket_name",""}};
  }

  bool check_if_all_required_keys_are_present(ConfMap &conf_map)
  {
    for (const auto& elem : conf_map)
      if (elem.second.empty())
      {
        std::string err_msg("Configuration file does not contain field: ");
        err_msg += elem.first;
        logger->log(MY_ERROR_LEVEL, err_msg.c_str());
        return true;
      }
    return false;
  }

  bool get_next_text_between_quotes(std::string &text, std::string &text_between_quotes,
                                    size_t start_pos, size_t &quotes_end_pos)
  {
    std::size_t quotes_start_pos = text.find('"', start_pos);
    if (quotes_start_pos == std::string::npos)
      return true; 
    quotes_end_pos = text.find('"', quotes_start_pos + 1);
    if (quotes_end_pos == std::string::npos)
      return true;
    text_between_quotes = text.substr(quotes_start_pos+1, quotes_end_pos - quotes_start_pos - 1);
    return false;
  }

  bool parse_line(std::string &line, std::string &key, std::string &value)
  {
    size_t quotes_end_pos;
    return get_next_text_between_quotes(line, key, 0, quotes_end_pos) ||
           quotes_end_pos + 1 >= line.length() ||
           get_next_text_between_quotes(line, value, quotes_end_pos + 1, quotes_end_pos);
   }

};

} //namespace keyring

#endif // SMART_LOOP_GKMS_CONF_PARSER_H
