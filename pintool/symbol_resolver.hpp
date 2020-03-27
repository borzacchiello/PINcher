#ifndef SYMBOL_RESOLVER_H
#define SYMBOL_RESOLVER_H

#include "option_manager.hpp"
#include <iostream>
#include <map>

extern OptionManager* g_option_manager;

using namespace std;

class SymbolResolver
{
  private:
    map<string, unsigned>                      module_name_to_id;
    map<unsigned, string>                      module_id_to_name;
    map<unsigned, map<string, unsigned long>>  symbol_to_address;
    map<unsigned long, pair<unsigned, string>> address_to_symbol;

  public:
    SymbolResolver();
    ~SymbolResolver();

    void add_module(unsigned module_id, string& module_name);
    void add_symbol(unsigned long address, unsigned module_id, string& symbol);
    bool get_symbol_address(string& symbol, unsigned module_id,
                            unsigned long* res);
    bool get_symbol_at(unsigned long address, pair<unsigned, string>* res);
    string   get_module_name(unsigned module_id);
    unsigned get_module_id(string& name);
    void     print_all_symbols(ostream& out, unsigned module_id);
    void     print_symbols(ostream& out, unsigned module_id);
};

#endif