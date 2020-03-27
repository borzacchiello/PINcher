#include "module_info.hpp"

ADDRINT ModuleInfo::get_img_base(unsigned id) {
    if (img_id_to_base.find(id) == img_id_to_base.end())
        return 0;
    return img_id_to_base[id]; 
}

void ModuleInfo::add_img(unsigned id, ADDRINT base)
{
    img_id_to_base[id] = base;
}
