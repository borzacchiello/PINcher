#include <regex.h>
#include <stdlib.h>
#include "function_breakpoint.hpp"
#include "symbol_resolver.hpp"
#include "module_info.hpp"
#include "util.hpp"

using namespace std;
extern SymbolResolver g_symbol_resolver;
extern ModuleInfo*    g_module_info;

FunctionBreakpoint::FunctionBreakpoint(map<string, string>& dict)
{
    auto _cc = dict.find("calling_convention");
    if (_cc == dict.end())
        calling_convention = "cdecl";
    else
        calling_convention = _cc->second;

    auto _module_name = dict.find("module");
    if (_module_name == dict.end())
        module_name = "";
    else
        module_name = _module_name->second;

    auto _num_args = dict.find("args");
    if (_num_args == dict.end())
        num_args = 0;
    else
        num_args = atoi(_num_args->second.c_str());

    auto _dump_args = dict.find("dump_args");
    if (_dump_args == dict.end())
        dump_args = 0;
    else {
        unsigned base = is_number(_dump_args->second);
        if (base == 0) {
            cerr << "[ERROR FunctionBreakpoint] " << _dump_args->second
                 << " is not a valid return value" << endl;
            exit(1);
        }
        dump_args = strtol(_dump_args->second.c_str(), NULL, base);
    }

    auto _dump_callstack = dict.find("bt");
    if (_dump_callstack == dict.end())
        dump_callstack = false;
    else
        dump_callstack = _dump_callstack->second == "0" ? false : true;

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
        unsigned base    = is_number(_ret_value->second);
        if (base == 0) {
            cerr << "[ERROR FunctionBreakpoint] " << _ret_value->second
                 << " is not a valid return value" << endl;
            exit(1);
        }
        new_ret_value = strtol(_ret_value->second.c_str(), NULL, base);
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
        << "\tNumArgs           = " << dec << num_args << endl
        << "\tDumpArgs          = " << dec << dump_args << endl
        << "\tSkip              = " << skip << endl
        << "\tChangeRetValue    = " << change_ret_value << endl
        << "\tNewRetValue       = 0x" << hex << new_ret_value << endl
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
    unsigned module_id = 1;
    if (module_name != "" && g_module_info->was_loaded_module(module_name)) {
        module_id = g_symbol_resolver.get_module_id(module_name);
    }
    unsigned long base_address = g_module_info->get_img_base(module_id);
    return base_address + address == _address;
}

void FunctionBreakpointAddress::dump(ostream& out)
{
    out << "FunctionBreakpointAddress {" << endl
        << "\tAddress           = 0x" << hex << address << endl
        << "\tModule            = "
        << (module_name == "" ? "main_module" : module_name) << endl
        << "\tCallingConvention = " << calling_convention << endl
        << "\tNumArgs           = " << dec << num_args << endl
        << "\tDumpArgs          = " << dec << dump_args << endl
        << "\tSkip              = " << skip << endl
        << "\tChangeRetValue    = " << change_ret_value << endl
        << "\tNewRetValue       = 0x" << hex << new_ret_value << endl
        << "}" << endl;
}
