#ifndef MODULE_INFO_H
#define MODULE_INFO_H

#include <map>
#include "pin.H"

using namespace std;

class ModuleInfo
{
  private:
    map<unsigned, pair<ADDRINT, ADDRINT>> img_id_to_base;

  public:
    ModuleInfo() {}

    ADDRINT get_img_base(unsigned id);
    void    add_img(unsigned id, ADDRINT base, ADDRINT end);
    int     get_module_id(ADDRINT address);
    bool    was_loaded_module(unsigned id);
    bool    was_loaded_module(string& name);
};

#endif