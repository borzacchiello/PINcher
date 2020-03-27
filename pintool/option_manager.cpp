#include "option_manager.hpp"
#include "symbol_resolver.hpp"
#include <iostream>
#include <map>

using namespace std;

#define MODULE_SYMBOL_SEPARATOR '#'
#define KEY_VALUE_SEPARATOR ':'
#define DICT_VALUES_SEPARATOR ','

static unsigned is_number(const string& s)
{
    unsigned i    = 0;
    unsigned base = 10;

    if (s.size() > 2 && s[0] == '0' && s[1] == 'x') {
        base = 16;
        i    = 2;
    }

    for (; i < s.size(); ++i) {
        if (base == 10 && !isdigit(s[i])) {
            base = 0;
            break;
        } else if (base == 16 && !isxdigit(s[i])) {
            base = 0;
            break;
        }
    }

    return base;
}

static int parse_param(const string& cmd, size_t start, string& param_value,
                       map<string, string>& param_dict)
{
    enum class State { ParamValue, Key, Value };

    State  state{State::ParamValue};
    size_t index = start;

    auto peek = [&](int offset = 0) -> char {
        if (index + offset >= cmd.size())
            return 0;
        return cmd[index + offset];
    };

    auto consume = [&]() -> char {
        assert(index < cmd.size());
        return cmd[index++];
    };

    vector<char> buffer;
    string       tmp_key;
    string       tmp_value;

    auto commit_and_advance_to = [&](auto& output, State new_state) {
        output = std::string(buffer.begin(), buffer.end());
        buffer.clear();
        state = new_state;
    };

    while (index < cmd.size()) {
        if (buffer.size() > 256)
            return -1;
        switch (state) {
            case State::ParamValue:
                if (peek() == DICT_VALUES_SEPARATOR) {
                    consume();
                    commit_and_advance_to(param_value, State::Key);
                    break;
                } else if (peek() == KEY_VALUE_SEPARATOR || peek() == ' ' ||
                           peek() == '\t')
                    return -1;

                buffer.push_back(consume());
                break;
            case State::Key:
                if (peek() == KEY_VALUE_SEPARATOR) {
                    consume();
                    commit_and_advance_to(tmp_key, State::Value);
                    break;
                } else if (peek() == DICT_VALUES_SEPARATOR || peek() == ' ' ||
                           peek() == '\t')
                    return -1;

                buffer.push_back(consume());
                break;
            case State::Value:
                if (peek() == DICT_VALUES_SEPARATOR) {
                    consume();
                    commit_and_advance_to(tmp_value, State::Key);
                    param_dict[tmp_key] = tmp_value;
                    break;
                } else if (peek() == KEY_VALUE_SEPARATOR || peek() == ' ' ||
                           peek() == '\t')
                    return -1;

                buffer.push_back(consume());
                break;
        }
    }

    if (state == State::ParamValue)
        param_value = std::string(buffer.begin(), buffer.end());
    else
        param_dict[tmp_key] = std::string(buffer.begin(), buffer.end());

    return 0;
}

void OptionManager::handle_print_symb_regex(const string& print_symb_argv)
{
    if (print_symb_argv.empty()) {
        has_symb_regex = false;
        return;
    }
    int res = regcomp(&print_symb_regex, print_symb_argv.c_str(), REG_EXTENDED);
    if (res == -1) {
        cerr << "[OptionManager] ERROR " << print_symb_argv
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
        cerr << "[OptionManager] ERROR \"" << bpf
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

OptionManager::OptionManager(KNOB<string>& print_symb_argv,
                             KNOB<string>& bpf_list)
{
    handle_print_symb_regex(print_symb_argv.Value());

    auto bpf_num = bpf_list.NumberOfValues();
    for (unsigned i = 0; i < bpf_num; ++i)
        handle_bpf(bpf_list.Value(i));
}

OptionManager::~OptionManager()
{
    for (auto p : bpf_list) {
        delete p;
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