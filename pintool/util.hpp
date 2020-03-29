#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <vector>
#include <map>
#include "pin.H"

extern map<string, LEVEL_BASE::REG> reg_map;
extern map<LEVEL_BASE::REG, string> inverted_reg_map;

unsigned is_number(const std::string& s);
int      is_double(const std::string& s);
int      parse_list(const std::string& cmd, std::vector<std::string>& out_list);
int parse_param(const std::string& cmd, size_t start, std::string& param_value,
                std::map<std::string, std::string>& param_dict);

#endif