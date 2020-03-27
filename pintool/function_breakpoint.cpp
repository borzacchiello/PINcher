#include "function_breakpoint.hpp"
#include <regex.h>
#include <stdlib.h>

FunctionBreakpoint::FunctionBreakpoint(map<string, string>& dict)
{
    auto _cc = dict.find("calling_convention");
    if (_cc == dict.end())
        calling_convention = "cdecl";
    else
        calling_convention = _cc->second;

    auto _num_args = dict.find("args");
    if (_num_args == dict.end())
        num_args = 0;
    else
        num_args = atoi(_num_args->second.c_str());

    auto _skip = dict.find("skip");
    if (_skip == dict.end())
        skip = false;
    else
        skip = _skip->second == "0" ? false : true;

    auto _ret_value = dict.find("rt");
    if (_ret_value == dict.end()) {
        change_ret_value = false;
        new_ret_value    = 0;
    } else {
        change_ret_value = true;
        new_ret_value    = atoi(_ret_value->second.c_str());
    }
}

FunctionBreakpointRegex::FunctionBreakpointRegex(string& _name_regex,
                                                 map<string, string>& dict)
    : FunctionBreakpoint(dict)
{
    name_regex = _name_regex;
}

bool FunctionBreakpointRegex::should_instrument(unsigned long _address,
                                                string&       name)
{
    regex_t regex;
    int     res = regcomp(&regex, name_regex.c_str(), REG_EXTENDED);
    if (res == -1) {
        cerr << "[FunctionBreakpointRegex] ERROR \"" << name
             << "\" is not a valid regex\n";
        exit(1);
    }
    if (regexec(&regex, name.c_str(), 0, NULL, 0) == 0)
        return true;
    return false;
}

void FunctionBreakpointRegex::dump(ostream& out)
{
    out << "FunctionBreakpointRegex {" << endl
        << "\tNameRegex         = " << name_regex << endl
        << "\tCallingConvention = " << calling_convention << endl
        << "\tNumArgs           = " << num_args << endl
        << "\tSkip              = " << skip << endl
        << "\tChangeRetValue    = " << change_ret_value << endl
        << "\tNewRetValue       = " << new_ret_value << endl
        << "}" << endl;
}

FunctionBreakpointAddress::FunctionBreakpointAddress(unsigned long _address,
                                                     map<string, string>& dict)
    : FunctionBreakpoint(dict)
{
    address = _address;
}

bool FunctionBreakpointAddress::should_instrument(unsigned long _address,
                                                  string&       name)
{
    return _address == address;
}

void FunctionBreakpointAddress::dump(ostream& out)
{
    out << "FunctionBreakpointAddress {" << endl
        << "\tAddress           = 0x" << hex << address << endl
        << "\tCallingConvention = " << calling_convention << endl
        << "\tNumArgs           = " << num_args << endl
        << "\tSkip              = " << skip << endl
        << "\tChangeRetValue    = " << change_ret_value << endl
        << "\tNewRetValue       = " << new_ret_value << endl
        << "}" << endl;
}
