#ifndef INSTRUCTION_BREAKPOINT_H
#define INSTRUCTION_BREAKPOINT_H

#include <iostream>
#include <map>
#include <set>
#include "pin.H"

using namespace std;

void init_reg_map();

class InstructionBreakpoint
{
  protected:
    unsigned long                                  address;
    string                                         module_name;
    map<LEVEL_BASE::REG, unsigned long>            set_map;
    map<LEVEL_BASE::REG, unsigned>                 dump_reg_map;
    map<pair<LEVEL_BASE::REG, unsigned>, unsigned> dump_reg_offset_map;
    map<pair<string, unsigned long>, unsigned>     dump_mem_map;

  public:
    InstructionBreakpoint(unsigned long address, map<string, string>& dict);

    map<LEVEL_BASE::REG, unsigned long>& get_set_map() { return set_map; }
    map<LEVEL_BASE::REG, unsigned>& get_dump_reg_map() { return dump_reg_map; }

    bool should_instrument(unsigned long address);
    void dump(ostream& out);
};

#endif