#ifndef FUNCTION_BREAKPOINT_H
#define FUNCTION_BREAKPOINT_H

#include "pin.H"
#include <iostream>
#include <map>
#include <string>

using namespace std;

class FunctionBreakpoint
{
  protected:
    string   calling_convention;
    string   module_name;
    unsigned num_args;
    bool     skip;
    bool     change_ret_value;
    size_t   new_ret_value;
    FunctionBreakpoint(map<string, string>& dict);

  public:
    virtual ~FunctionBreakpoint() {}

    void instrument_function();

    unsigned     get_num_args() { return num_args; }
    bool         must_change_ret_value() { return change_ret_value; }
    size_t       get_new_ret_value() { return new_ret_value; }
    bool         must_skip() { return skip; }
    virtual void dump(ostream& out)                                     = 0;
    virtual bool should_instrument(unsigned long address, string& name) = 0;
};

class FunctionBreakpointRegex : public FunctionBreakpoint
{
  private:
    string name_regex;

  public:
    FunctionBreakpointRegex(string& name_regex, map<string, string>& dict);
    ~FunctionBreakpointRegex() {}

    virtual void dump(ostream& out);
    virtual bool should_instrument(unsigned long address, string& name);
};

class FunctionBreakpointAddress : public FunctionBreakpoint
{
  private:
    unsigned long address;

  public:
    FunctionBreakpointAddress(unsigned long address, map<string, string>& dict);
    ~FunctionBreakpointAddress() {}

    virtual void dump(ostream& out);
    virtual bool should_instrument(unsigned long address, string& name);
};

#endif
