#include "my_config.h"
//#include <boost/tokenizer.hpp>
//#include <boost/algorithm/string/erase.hpp>
#include <string>
#include <fstream>
#include <map>

namespace keyring {

class Gkms_conf_parser
{
public:
  typedef std::map<std::string, std::string> ConfMap;

  bool parse_file(std::string &conf_file_path, ConfMap &conf_map)
  {
    std::ifstream fs;
    fs.open(conf_file_path.c_str(), std::fstream::in);
    std::string line, key, value;
    while(std::getline(fs, line))
    {
      parse_line(line, key, value);
      conf_map[key] = value;
    }
    return false;
  }
protected:
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
