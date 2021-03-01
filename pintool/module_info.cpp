#include "module_info.hpp"
#include "symbol_resolver.hpp"

extern SymbolResolver g_symbol_resolver;

ADDRINT ModuleInfo::get_img_base(unsigned id)
{
    if (img_id_to_base.find(id) == img_id_to_base.end())
        return 0;
    return img_id_to_base[id].first;
}

void ModuleInfo::add_img(unsigned id, ADDRINT base, ADDRINT end)
{
    img_id_to_base[id] = make_pair(base, end);
}

int ModuleInfo::get_module_id(ADDRINT address)
{
    for (auto it = img_id_to_base.begin(); it != img_id_to_base.end(); it++) {
        auto pair = it->second;
        if (address >= pair.first && address <= pair.second)
            return it->first;
    }

    return -1;
}

bool ModuleInfo::was_loaded_module(unsigned id)
{
    return img_id_to_base.find(id) != img_id_to_base.end();
}

bool ModuleInfo::was_loaded_module(string& name)
{
    return g_symbol_resolver.exists_module_name(name);
}