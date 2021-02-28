#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include "option_manager.hpp"
#include "symbol_resolver.hpp"
#include "util.hpp"

using namespace std;

#define MODULE_SYMBOL_SEPARATOR '#'

void OptionManager::handle_print_symb_regex(const string& print_symb_argv)
{
    if (print_symb_argv.empty()) {
        has_symb_regex = false;
        return;
    }
    int res = regcomp(&print_symb_regex, print_symb_argv.c_str(), REG_EXTENDED);
    if (res == -1) {
        cerr << "[ERROR OptionManager] " << print_symb_argv
             << " is not a regular expression\n";
        exit(1);
    }
    has_symb_regex = true;
}

void OptionManager::handle_bpf(const string& bpf)
{
    // module#function,opt1:val1,opt2:val2...optn:valn
    string              value;
    map<string, string> dict;
    int                 res = parse_param(bpf, 0, value, dict);

    if (res == -1) {
        cerr << "[ERROR OptionManager] \"" << bpf
             << "\" is not a valid bpf argument\n";
        exit(1);
    }

    FunctionBreakpoint* fp;
    unsigned            base = is_number(value);
    if (base != 0) {
        fp = static_cast<FunctionBreakpoint*>(new FunctionBreakpointAddress(
            strtol(value.c_str(), NULL, base), dict));
    } else {
        fp = static_cast<FunctionBreakpoint*>(
            new FunctionBreakpointRegex(value, dict));
    }

    bpf_list.push_back(fp);
    // fp->dump(cerr);
}

void OptionManager::handle_bpx(const string& bpf)
{
    // module#function,opt1:val1,opt2:val2...optn:valn
    string              value;
    map<string, string> dict;
    int                 res = parse_param(bpf, 0, value, dict);

    if (res == -1) {
        cerr << "[ERROR OptionManager]  \"" << bpf
             << "\" is not a valid bpx argument\n";
        exit(1);
    }

    InstructionBreakpoint* ib;
    unsigned               base = is_number(value);
    if (base == 0) {
        cerr << "[ERROR OptionManager]  \"" << value
             << "\" is not a valid address\n";
        exit(1);
    }
    ib = new InstructionBreakpoint(strtol(value.c_str(), NULL, base), dict);

    bpx_list.push_back(ib);
    // ib->dump(cerr);
}

OptionManager::OptionManager(KNOB<string>& print_symb_argv,
                             KNOB<string>& dump_callgraph,
                             KNOB<string>& bpf_list, KNOB<string>& bpx_list)
{
    handle_print_symb_regex(print_symb_argv.Value());
    callgraph_filename = dump_callgraph.Value();

    auto bpf_num = bpf_list.NumberOfValues();
    for (unsigned i = 0; i < bpf_num; ++i)
        handle_bpf(bpf_list.Value(i));

    auto bpx_num = bpx_list.NumberOfValues();
    for (unsigned i = 0; i < bpx_num; ++i)
        handle_bpx(bpx_list.Value(i));
}

OptionManager::~OptionManager()
{
    for (auto p : bpf_list) {
        delete p;
    }

    if (!callgraph_filename.empty()) {
        dump_callgraph();
    }
}

bool OptionManager::SYMB_must_be_printed(string& module_name,
                                         string& symbol_name)
{
    auto string_to_match =
        (module_name + MODULE_SYMBOL_SEPARATOR + symbol_name).c_str();
    if (has_symb_regex &&
        (regexec(&print_symb_regex, string_to_match, 0, NULL, 0) == 0)) {
        return true;
    }
    return false;
}

FunctionBreakpoint* OptionManager::BPF_must_instrument(unsigned long pc)
{
    pair<unsigned, string> moduleid_name;
    bool   is_symbol   = g_symbol_resolver.get_symbol_at(pc, &moduleid_name);
    string symbol_name = is_symbol ? moduleid_name.second : "";

    for (auto it = bpf_list.begin(); it != bpf_list.end(); ++it) {
        FunctionBreakpoint* f = *it;
        if (f->should_instrument(pc, symbol_name))
            return f;
    }
    return NULL;
}

InstructionBreakpoint* OptionManager::BPX_must_instrument(unsigned long pc)
{
    for (auto it = bpx_list.begin(); it != bpx_list.end(); ++it) {
        InstructionBreakpoint* ib = *it;
        if (ib->should_instrument(pc))
            return ib;
    }
    return NULL;
}

void OptionManager::CALLGRAPH_add_edge(unsigned long src, unsigned long dst)
{
    callgraph_edges.insert(make_pair(src, dst));
}

void OptionManager::dump_callgraph()
{
    ofstream out(callgraph_filename.c_str());
    if (!out.is_open()) {
        cerr << "[ERROR OptionManager]  \"" << callgraph_filename
             << "\" is not a valid filename\n";
        return;
    }

    pair<unsigned, string> moduleid_name_src, moduleid_name_dst;

    out << "digraph {" << endl
        << "\tnode [shape=box];" << endl
        << "\tnode [fontname = \"monospace\"];" << endl;
    for (auto edge : callgraph_edges) {

        int module_id_src = g_module_info->get_module_id(edge.first);
        int module_id_dst = g_module_info->get_module_id(edge.second);

        if (module_id_src != 1 || module_id_dst != 1)
            // I'm interested in function calls of the main image
            continue;

        bool ret_src =
            g_symbol_resolver.get_symbol_at(edge.first, &moduleid_name_src);
        bool ret_dst =
            g_symbol_resolver.get_symbol_at(edge.second, &moduleid_name_dst);

        if (!ret_src || !ret_dst)
            // If no symbols for either SRC or DST, continue.
            // Change this if you want to include functions without symbols in
            // callgraph
            continue;

        out << "\t\""
            << (ret_src ? moduleid_name_src.second : hexstr(edge.first))
            << "\" -> "
            << "\""
            << (ret_dst ? moduleid_name_dst.second : hexstr(edge.second))
            << "\";" << endl;
    }
    out << "}" << endl;
    out.close();
}