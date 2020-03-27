#include "module_info.hpp"

ADDRINT ModuleInfo::get_img_base(unsigned id)
{
    if (img_id_to_base.find(id) == img_id_to_base.end())
        return 0;
    return img_id_to_base[id];
}

void ModuleInfo::add_img(unsigned id, ADDRINT base)
{
    img_id_to_base[id] = base;
}

int ModuleInfo::get_module_id(ADDRINT address)
{
    // todo use interval tree
    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
            if (address >= SEC_Address(sec) &&
                address < SEC_Address(sec) + SEC_Size(sec))
                return IMG_Id(img);

    return -1;
}
