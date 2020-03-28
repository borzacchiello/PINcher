#ifndef OPTION_MANAGER_H
#define OPTION_MANAGER_H

#include "function_breakpoint.hpp"
#include "instruction_breakpoint.hpp"
#include "pin.H"
#include <regex.h>
#include <string>
#include <vector>

class SymbolResolver;
extern SymbolResolver g_symbol_resolver;

using namespace std;

class OptionManager
{
  private:
    bool                           has_symb_regex;
    regex_t                        print_symb_regex;
    vector<FunctionBreakpoint*>    bpf_list;
    vector<InstructionBreakpoint*> bpx_list;

    void handle_print_symb_regex(const string& print_symb_argv);
    void handle_bpf(const string& bpf);
    void handle_bpx(const string& bpx);

  public:
    OptionManager(KNOB<string>& print_symb_argv, KNOB<string>& bpf_list,
                  KNOB<string>& bpx_list);
    ~OptionManager();

    bool SYMB_is_set() { return has_symb_regex; }
    bool SYMB_must_be_printed(string& module_name, string& symbol_name);

    FunctionBreakpoint*    BPF_must_instrument(unsigned long address);
    InstructionBreakpoint* BPX_must_instrument(unsigned long pc);
};

#endif
