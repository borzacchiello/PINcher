#ifndef FUNCTION_INFO_H
#define FUNCTION_INFO_H

#include <string>

struct FunctionInfo {
    unsigned long callsite;
    long          callsite_offset;
    unsigned long function_addr;
    std::string   function_name;
    unsigned long ret_address;
    unsigned long ret_value;
    bool          modify_ret_value;
    bool          print_ret;
};

#endif