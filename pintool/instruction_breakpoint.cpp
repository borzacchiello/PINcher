#include <iostream>
#include <stdlib.h>
#include "instruction_breakpoint.hpp"
#include "symbol_resolver.hpp"
#include "module_info.hpp"
#include "util.hpp"

extern SymbolResolver g_symbol_resolver;
extern ModuleInfo*    g_module_info;

static LEVEL_BASE::REG get_reg_or_die(string& reg_name)
{
    auto it = reg_map.find(reg_name);
    if (it == reg_map.end()) {
        cerr << "[ERROR InstructionBreakpoint] " << reg_name
             << " is not a valid register" << endl;
        exit(1);
    }
    return it->second;
}

static unsigned long get_value_or_die(string& value_str)
{
    unsigned base = is_number(value_str);
    if (base == 0) {
        cerr << "[ERROR InstructionBreakpoint] " << value_str
             << " is not a valid number" << endl;
        exit(1);
    }
    return strtol(value_str.c_str(), NULL, base);
}

static double get_fp_value_of_die(string& value_str)
{
    if (!is_double(value_str)) {
        cerr << "[ERROR InstructionBreakpoint] " << value_str
             << " is not a valid floating point value" << endl;
        exit(1);
    }

    return atof(value_str.c_str());
}

InstructionBreakpoint::InstructionBreakpoint(unsigned long        _address,
                                             map<string, string>& dict)
    : address(_address)
{
    // find a better way...
    init_reg_map();

    auto _module_name = dict.find("module");
    if (_module_name == dict.end())
        module_name = "";
    else
        module_name = _module_name->second;

    auto set_regs = dict.find("set_regs");
    auto set_vals = dict.find("set_vals");
    if (set_regs != dict.end()) {
        if (set_vals == dict.end()) {
            cerr << "[ERROR InstructionBreakpoint] set_regs without set_vals"
                 << endl;
            exit(1);
        }
        string         unprocessed_regs_list = set_regs->second;
        vector<string> processed_regs_list;
        auto res_regs = parse_list(unprocessed_regs_list, processed_regs_list);
        if (res_regs == -1) {
            cerr << "[ERROR InstructionBreakpoint] " << unprocessed_regs_list
                 << " is not a valid list for set_regs" << endl;
            exit(1);
        }
        string         unprocessed_vals_list = set_vals->second;
        vector<string> processed_vals_list;
        auto res_vals = parse_list(unprocessed_vals_list, processed_vals_list);
        if (res_vals == -1) {
            cerr << "[ERROR InstructionBreakpoint] " << unprocessed_vals_list
                 << " is not a valid list for set_vals" << endl;
            exit(1);
        }
        if (processed_vals_list.size() != processed_regs_list.size()) {
            cerr << "[ERROR InstructionBreakpoint] different set_regs and "
                    "set_vals len"
                 << endl;
            exit(1);
        }

        for (unsigned i = 0; i < processed_regs_list.size(); ++i) {
            set_map[get_reg_or_die(processed_regs_list[i])] =
                get_value_or_die(processed_vals_list[i]);
        }
    }

    auto set_fp_regs = dict.find("set_fp_regs");
    auto set_fp_vals = dict.find("set_fp_vals");
    if (set_fp_regs != dict.end()) {
        if (set_fp_vals == dict.end()) {
            cerr << "[ERROR InstructionBreakpoint] set_fp_regs without "
                    "set_fp_vals"
                 << endl;
            exit(1);
        }
        string         unprocessed_regs_list = set_fp_regs->second;
        vector<string> processed_regs_list;
        auto res_regs = parse_list(unprocessed_regs_list, processed_regs_list);
        if (res_regs == -1) {
            cerr << "[ERROR InstructionBreakpoint] " << unprocessed_regs_list
                 << " is not a valid list for set_fp_regs" << endl;
            exit(1);
        }
        string         unprocessed_vals_list = set_fp_vals->second;
        vector<string> processed_vals_list;
        auto res_vals = parse_list(unprocessed_vals_list, processed_vals_list);
        if (res_vals == -1) {
            cerr << "[ERROR InstructionBreakpoint] " << unprocessed_vals_list
                 << " is not a valid list for set_fp_vals" << endl;
            exit(1);
        }
        if (processed_vals_list.size() != processed_regs_list.size()) {
            cerr << "[ERROR InstructionBreakpoint] different set_fp_regs and "
                    "set_fp_vals len"
                 << endl;
            exit(1);
        }

        for (unsigned i = 0; i < processed_regs_list.size(); ++i) {
            set_fp_map[get_reg_or_die(processed_regs_list[i])] =
                get_fp_value_of_die(processed_vals_list[i]);
        }
    }

    auto dump_regs    = dict.find("dump_regs");
    auto dump_lengths = dict.find("dump_lengths");
    if (dump_regs != dict.end()) {
        if (dump_lengths == dict.end()) {
            cerr << "[ERROR InstructionBreakpoint] dump_regs without "
                    "dump_lengths"
                 << endl;
            exit(1);
        }
        string         unprocessed_regs_list = dump_regs->second;
        vector<string> processed_regs_list;
        auto res_regs = parse_list(unprocessed_regs_list, processed_regs_list);
        if (res_regs == -1) {
            cerr << "[ERROR InstructionBreakpoint] " << unprocessed_regs_list
                 << " is not a valid list for dump_regs" << endl;
            exit(1);
        }
        string         unprocessed_lengths_list = dump_lengths->second;
        vector<string> processed_lengths_list;
        auto           res_lengths =
            parse_list(unprocessed_lengths_list, processed_lengths_list);
        if (res_lengths == -1) {
            cerr << "[ERROR InstructionBreakpoint] " << unprocessed_lengths_list
                 << " is not a valid list for dump_lengths" << endl;
            exit(1);
        }
        if (processed_lengths_list.size() != processed_regs_list.size()) {
            cerr << "[ERROR InstructionBreakpoint] different dump_regs and "
                    "dump_lengths len "
                 << processed_regs_list.size() << " "
                 << processed_lengths_list.size() << endl;
            exit(1);
        }

        for (unsigned i = 0; i < processed_regs_list.size(); ++i) {
            dump_reg_map[get_reg_or_die(processed_regs_list[i])] =
                get_value_or_die(processed_lengths_list[i]);
        }
    }
}

bool InstructionBreakpoint::should_instrument(unsigned long address_)
{
    unsigned module_id = 1;
    if (module_name != "" && g_module_info->was_loaded_module(module_name)) {
        module_id = g_symbol_resolver.get_module_id(module_name);
    }
    unsigned long base_address = g_module_info->get_img_base(module_id);
    return base_address + address == address_;
}

void InstructionBreakpoint::dump(ostream& out)
{
    out << "InstructionBreakpoint {" << endl;
    out << "  Address: 0x" << hex << address << endl;
    out << "  Module:  " << (module_name == "" ? "main_module" : module_name)
        << endl;
    auto itset = set_map.begin();
    while (itset != set_map.end()) {
        LEVEL_BASE::REG reg_id  = itset->first;
        unsigned long   reg_val = itset->second;
        out << "  SET(" << inverted_reg_map[reg_id] << ", 0x" << hex << reg_val
            << ")" << endl;
        itset++;
    }
    auto it_fp_set = set_fp_map.begin();
    while (it_fp_set != set_fp_map.end()) {
        LEVEL_BASE::REG reg_id  = it_fp_set->first;
        double          reg_val = it_fp_set->second;
        out << "  SET(" << inverted_reg_map[reg_id] << ", " << reg_val << ")"
            << endl;
        it_fp_set++;
    }
    auto itdump_reg = dump_reg_map.begin();
    while (itdump_reg != dump_reg_map.end()) {
        LEVEL_BASE::REG reg_id  = itdump_reg->first;
        unsigned        reg_len = itdump_reg->second;
        out << "  DUMP(" << inverted_reg_map[reg_id] << ", 0x" << hex << reg_len
            << ")" << endl;
        itdump_reg++;
    }
    out << "}" << endl;
}