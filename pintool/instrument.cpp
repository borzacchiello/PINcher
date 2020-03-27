#include "instrument.hpp"
#include "function_info.hpp"
#include "symbol_resolver.hpp"
#include <assert.h>
#include <iostream>
#include <stack>
#include <unistd.h>

using namespace std;
extern SymbolResolver      g_symbol_resolver;
extern stack<FunctionInfo> g_call_stack;

ostream& out = cerr;

static unsigned long get_function_arg_k(CONTEXT* ctx, unsigned k)
{
    unsigned long res = 0;
    switch (k) {
        case 0: {
            PIN_GetContextRegval(ctx, REG_RDI, (UINT8*)&res);
            break;
        }
        case 1: {
            PIN_GetContextRegval(ctx, REG_RSI, (UINT8*)&res);
            break;
        }
        case 2: {
            PIN_GetContextRegval(ctx, REG_RCX, (UINT8*)&res);
            break;
        }

        default:
            break;
    }
    return res;
}

static bool is_mapped(ADDRINT addr)
{
    // The canonical way is to use the write() system call to read from the page
    // (writing to a dummy pipe() file descriptor). Instead of faulting, it will
    // return -1 with errno == EFAULT if the buffer passed to write() is
    // unreadable.
    int fd[2];
    pipe(fd);
    int res = write(fd[1], (char*)addr, 1);
    close(fd[0]);
    close(fd[1]);

    return res != -1;
}

static unsigned long is_string(ADDRINT addr)
{
    char* c_p = (char*)addr;
    while (is_mapped((ADDRINT)c_p) && *c_p >= ' ' && *c_p <= '~')
        c_p++;

    return (unsigned long)c_p - (unsigned long)addr;
}

void instrumentBPF(FunctionBreakpoint* f, ADDRINT pc, CONTEXT* ctx)
{
    if (g_call_stack.size() == 0) {
        cerr << "ERROR: shadow call stack is empty in instrumentBPF\n";
        exit(1);
    }

    pair<unsigned, string> moduleid_name;
    bool ret = g_symbol_resolver.get_symbol_at(pc, &moduleid_name);

    out << "<triggered bpf>\t" << (ret ? moduleid_name.second : "unknown");

    out << " ( ";
    if (f->get_num_args() > 0) {
        unsigned long param_k = get_function_arg_k(ctx, 0);
        unsigned long s_len   = is_string(param_k);
        out << "0x" << hex << param_k;
        if (s_len > 0) {
            out << " \"";
            for (unsigned long j = 0; j < s_len; ++j) {
                out << ((char*)param_k)[j];
            }
            out << "\"";
        }
        for (unsigned i = 1; i < f->get_num_args(); ++i) {
            param_k = get_function_arg_k(ctx, i);
            s_len   = is_string(param_k);
            out << ", 0x" << hex << param_k;
            if (s_len > 0) {
                out << " \"";
                for (unsigned j = 0; j < s_len; ++j) {
                    out << ((char*)param_k)[j];
                }
                out << "\"";
            }
        }
    }
    out << " )";
    out << "  @  0x" << hex << pc;

    FunctionInfo fi = g_call_stack.top();
    if (f->must_skip()) {
        g_call_stack.pop();
        out << "  -  SKIPPED";
        if (f->must_change_ret_value()) {
            PIN_SetContextReg(ctx, REG_RAX, f->get_new_ret_value());
            out << " [ force ret -> 0x" << hex << f->get_new_ret_value()
                << " ]";
        }
        out << endl;
        PIN_SetContextReg(ctx, REG_INST_PTR, fi.ret_address);
        PIN_ExecuteAt(ctx);
    }

    if (f->must_change_ret_value()) {
        g_call_stack.pop();
        out << " [ force ret -> 0x" << hex << f->get_new_ret_value() << " ]";
        fi.modify_ret_value = true;
        fi.ret_value        = f->get_new_ret_value();
        g_call_stack.push(fi);
    }

    out << endl;
}