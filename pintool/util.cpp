#include <ctype.h>
#include <assert.h>
#include <map>
#include <vector>
#include "pin.H"

using namespace std;

#define KEY_VALUE_SEPARATOR ':'
#define DICT_VALUES_SEPARATOR ','
#define LIST_VALUES_SEPARATOR '-'

map<string, LEVEL_BASE::REG> reg_map;
map<LEVEL_BASE::REG, string> inverted_reg_map;
bool                         reg_map_initialized = false;

unsigned is_number(const string& s)
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

int is_double(const std::string& s)
{
    bool point_encountered = false;
    for (unsigned i = 0; i < s.size(); ++i) {
        if (s[i] == '.') {
            if (point_encountered)
                return 0;
            point_encountered = true;
        } else if (!isdigit(s[i]))
            return 0;
    }
    return 1;
}

int parse_list(const string& cmd, vector<string>& out_list)
{
    size_t       index = 0;
    string       tmp_v;
    vector<char> buffer;

    auto peek = [&](int offset = 0) -> char {
        if (index + offset >= cmd.size())
            return 0;
        return cmd[index + offset];
    };

    auto consume = [&]() -> char {
        assert(index < cmd.size());
        return cmd[index++];
    };

    auto commit = [&](auto& output) {
        output = std::string(buffer.begin(), buffer.end());
        buffer.clear();
    };

    while (index < cmd.size()) {
        if (peek() == LIST_VALUES_SEPARATOR) {
            if (buffer.size() == 0)
                return -1;
            consume();
            commit(tmp_v);
            out_list.push_back(tmp_v);
        } else if (peek() == ' ' || peek() == '\t') {
            consume();
        } else {
            buffer.push_back(consume());
        }
    }
    if (buffer.size() == 0)
        return -1;
    commit(tmp_v);
    out_list.push_back(tmp_v);
    return 0;
}

int parse_param(const string& cmd, size_t start, string& param_value,
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

void init_reg_map()
{
    // there is a better way? [must be C++98 compliant]
    if (reg_map_initialized)
        return;
    reg_map["rax"]                        = LEVEL_BASE::REG_RAX;
    inverted_reg_map[LEVEL_BASE::REG_RAX] = "rax";
    reg_map["rbx"]                        = LEVEL_BASE::REG_RBX;
    inverted_reg_map[LEVEL_BASE::REG_RBX] = "rbx";
    reg_map["rcx"]                        = LEVEL_BASE::REG_RCX;
    inverted_reg_map[LEVEL_BASE::REG_RCX] = "rcx";
    reg_map["rdx"]                        = LEVEL_BASE::REG_RDX;
    inverted_reg_map[LEVEL_BASE::REG_RDX] = "rdx";
    reg_map["rsi"]                        = LEVEL_BASE::REG_RSI;
    inverted_reg_map[LEVEL_BASE::REG_RSI] = "rsi";
    reg_map["rdi"]                        = LEVEL_BASE::REG_RDI;
    inverted_reg_map[LEVEL_BASE::REG_RDI] = "rdi";
    reg_map["r8"]                         = LEVEL_BASE::REG_R8;
    inverted_reg_map[LEVEL_BASE::REG_R8]  = "r8";
    reg_map["r9"]                         = LEVEL_BASE::REG_R9;
    inverted_reg_map[LEVEL_BASE::REG_R9]  = "r9";
    reg_map["r10"]                        = LEVEL_BASE::REG_R10;
    inverted_reg_map[LEVEL_BASE::REG_R10] = "r10";
    reg_map["r11"]                        = LEVEL_BASE::REG_R11;
    inverted_reg_map[LEVEL_BASE::REG_R11] = "r11";
    reg_map["r12"]                        = LEVEL_BASE::REG_R12;
    inverted_reg_map[LEVEL_BASE::REG_R12] = "r12";
    reg_map["r13"]                        = LEVEL_BASE::REG_R13;
    inverted_reg_map[LEVEL_BASE::REG_R13] = "r13";
    reg_map["r14"]                        = LEVEL_BASE::REG_R14;
    inverted_reg_map[LEVEL_BASE::REG_R14] = "r14";
    reg_map["rsp"]                        = LEVEL_BASE::REG_RSP;
    inverted_reg_map[LEVEL_BASE::REG_RSP] = "rsp";
    reg_map["rbp"]                        = LEVEL_BASE::REG_RBP;
    inverted_reg_map[LEVEL_BASE::REG_RBP] = "rbp";

    reg_map["st0"]                         = LEVEL_BASE::REG_ST0;
    inverted_reg_map[LEVEL_BASE::REG_ST0]  = "st0";
    reg_map["st1"]                         = LEVEL_BASE::REG_ST1;
    inverted_reg_map[LEVEL_BASE::REG_ST1]  = "st1";
    reg_map["st2"]                         = LEVEL_BASE::REG_ST2;
    inverted_reg_map[LEVEL_BASE::REG_ST2]  = "st2";
    reg_map["st3"]                         = LEVEL_BASE::REG_ST3;
    inverted_reg_map[LEVEL_BASE::REG_ST3]  = "st3";
    reg_map["st4"]                         = LEVEL_BASE::REG_ST4;
    inverted_reg_map[LEVEL_BASE::REG_ST4]  = "st4";
    reg_map["st5"]                         = LEVEL_BASE::REG_ST5;
    inverted_reg_map[LEVEL_BASE::REG_ST5]  = "st5";
    reg_map["st6"]                         = LEVEL_BASE::REG_ST6;
    inverted_reg_map[LEVEL_BASE::REG_ST6]  = "st6";
    reg_map["st7"]                         = LEVEL_BASE::REG_ST7;
    inverted_reg_map[LEVEL_BASE::REG_ST7]  = "st7";
    reg_map["xmm0"]                        = LEVEL_BASE::REG_XMM0;
    inverted_reg_map[LEVEL_BASE::REG_XMM0] = "xmm0";
    reg_map["xmm1"]                        = LEVEL_BASE::REG_XMM1;
    inverted_reg_map[LEVEL_BASE::REG_XMM1] = "xmm1";
    reg_map["xmm2"]                        = LEVEL_BASE::REG_XMM2;
    inverted_reg_map[LEVEL_BASE::REG_XMM2] = "xmm2";
    reg_map["xmm3"]                        = LEVEL_BASE::REG_XMM3;
    inverted_reg_map[LEVEL_BASE::REG_XMM3] = "xmm3";
    reg_map["xmm4"]                        = LEVEL_BASE::REG_XMM4;
    inverted_reg_map[LEVEL_BASE::REG_XMM4] = "xmm4";
    reg_map["xmm5"]                        = LEVEL_BASE::REG_XMM5;
    inverted_reg_map[LEVEL_BASE::REG_XMM5] = "xmm5";
    reg_map["xmm6"]                        = LEVEL_BASE::REG_XMM6;
    inverted_reg_map[LEVEL_BASE::REG_XMM6] = "xmm6";
    reg_map["xmm7"]                        = LEVEL_BASE::REG_XMM7;
    inverted_reg_map[LEVEL_BASE::REG_XMM7] = "xmm7";

    reg_map_initialized = true;
}
