#include "symbol_resolver.hpp"
#include <string>

string extract_filename(const std::string& fullPath)
{
    const size_t lastSlashIndex = fullPath.find_last_of("/\\");
    return fullPath.substr(lastSlashIndex + 1);
}

SymbolResolver::SymbolResolver() {}
SymbolResolver::~SymbolResolver() {}

void SymbolResolver::add_module(unsigned module_id, string& _module_name)
{
    string            module_name = extract_filename(_module_name);
    pair<int, string> val1(module_id, module_name);
    pair<string, int> val2(module_name, module_id);
    module_id_to_name.insert(val1);
    module_name_to_id.insert(val2);
}

void SymbolResolver::add_symbol(unsigned long address, unsigned module_id,
                                string& _symbol)
{
    string                  symbol = _symbol;
    pair<unsigned, string&> mod_symb(module_id, symbol);

    auto it = symbol_to_address.find(module_id);
    if (it == symbol_to_address.end()) {
        map<string, unsigned long> v;
        symbol_to_address[module_id] = v;
    }
    symbol_to_address[module_id][symbol] = address;
    address_to_symbol[address]           = mod_symb;
}

bool SymbolResolver::get_symbol_address(string& symbol, unsigned module_id,
                                        unsigned long* res)
{
    auto it_1 = symbol_to_address.find(module_id);
    if (it_1 == symbol_to_address.end())
        return false;

    auto it_2 = it_1->second.find(symbol);
    if (it_2 == it_1->second.end())
        return false;
    *res = it_2->second;
    return true;
}

bool SymbolResolver::get_symbol_at(unsigned long           address,
                                   pair<unsigned, string>* res)
{
    auto it = address_to_symbol.find(address);
    if (it == address_to_symbol.end())
        return false;

    *res = it->second;
    return true;
}

string SymbolResolver::get_module_name(unsigned module_id)
{
    return module_id_to_name[module_id];
}

void SymbolResolver::print_all_symbols(ostream& out, unsigned module_id)
{
    auto symbols_in_module_it = symbol_to_address.find(module_id);
    if (symbols_in_module_it == symbol_to_address.end())
        return;

    string module_name = module_id_to_name[module_id];

    for (auto it = symbols_in_module_it->second.begin();
         it != symbols_in_module_it->second.end(); it++) {
        out << "SYMBOL:\t[Address] 0x" << hex << it->second << "\t[Module] "
            << module_name << "\t[SymbolName] " << it->first << endl;
    }
}

void SymbolResolver::print_symbols(ostream& out, unsigned module_id)
{
    if (!g_option_manager->SYMB_is_set())
        return;
    auto symbols_in_module_it = symbol_to_address.find(module_id);
    if (symbols_in_module_it == symbol_to_address.end())
        return;

    string module_name = module_id_to_name[module_id];

    for (auto it = symbols_in_module_it->second.begin();
         it != symbols_in_module_it->second.end(); it++) {
        if (g_option_manager->SYMB_must_be_printed(module_name,
                                                   (string&)it->first))
            out << "SYMBOL:\t[Address] 0x" << hex << it->second << "\t[Module] "
                << module_name << "\t[SymbolName] " << it->first << endl;
    }
}
