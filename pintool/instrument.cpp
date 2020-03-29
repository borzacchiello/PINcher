#include <assert.h>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <stack>
#include "fogetful_stack.hpp"
#include "instrument.hpp"
#include "function_info.hpp"
#include "symbol_resolver.hpp"
#include "module_info.hpp"
#include "util.hpp"

#define min(x, y) (x) < (y) ? (x) : (y)

#define LINE_SIZE 16

using namespace std;
extern SymbolResolver      g_symbol_resolver;
extern ForgetfulStack<FunctionInfo>* g_call_stack;
extern ModuleInfo*         g_module_info;

ostream& out = cerr;

VOID InstrumentCallAfter(ADDRINT call_pc, ADDRINT dest_pc, ADDRINT ret_pc)
{
    unsigned long caller_address = g_call_stack->top().function_addr;

    FunctionInfo fi;
    fi.callsite         = call_pc;
    fi.callsite_offset  = caller_address != 0 ? (call_pc - caller_address) : -1;
    fi.function_addr    = dest_pc;
    fi.function_name    = "";
    fi.ret_address      = ret_pc;
    fi.ret_value        = 0;
    fi.modify_ret_value = false;
    fi.print_ret        = false;

    g_call_stack->push(fi);
}

VOID InstrumentRet(ADDRINT* rax)
{
    FunctionInfo fi = g_call_stack->pop();

    if (fi.modify_ret_value)
        *rax = fi.ret_value;

    if (fi.print_ret)
        out << "<bpf end>  " << fi.function_name << " -> 0x" << hex << *rax
            << endl;
}

static void print_callstack()
{
    out << "\n  CALLSTACK" << endl;
    stack<FunctionInfo> call_stack_copy;

    unsigned size = g_call_stack->size() - 1;
    while (size-- > 0) {
        FunctionInfo f = g_call_stack->pop();

        int     caller_module_id = g_module_info->get_module_id(f.callsite);
        ADDRINT caller_module_base =
            g_module_info->get_img_base(caller_module_id);
        string caller_module_name =
            g_symbol_resolver.get_module_name(caller_module_id);

        out << "  >>> " << caller_module_name << "+0x"
            << f.callsite - caller_module_base;

        pair<unsigned, string> moduleid_name;
        bool                   ret = g_symbol_resolver.get_symbol_at(
            f.callsite - f.callsite_offset, &moduleid_name);
        if (ret)
            out << " ( " << moduleid_name.second << "+0x" << f.callsite_offset
                << " )";
        out << endl;

        call_stack_copy.push(f);
    }

    size = call_stack_copy.size();
    while (size-- > 0) {
        FunctionInfo f = call_stack_copy.top();
        call_stack_copy.pop();
        g_call_stack->push(f);
    }
}

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
            PIN_GetContextRegval(ctx, REG_RDX, (UINT8*)&res);
            break;
        }
        case 3: {
            PIN_GetContextRegval(ctx, REG_RCX, (UINT8*)&res);
            break;
        }
        case 4: {
            PIN_GetContextRegval(ctx, REG_R8, (UINT8*)&res);
            break;
        }
        case 5: {
            PIN_GetContextRegval(ctx, REG_R9, (UINT8*)&res);
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

static void dump_arg_line_k(ADDRINT arg, unsigned line_size)
{
    out << "0x" << setfill('0') << setw(16) << hex << arg << ": ";
    unsigned i = 0;
    for (; i < line_size; ++i) {
        if (is_mapped(arg + i)) {
            out << setfill('0') << setw(2) << hex
                << (unsigned)(*(char*)(arg + i) & 0xff) << " ";
        }
    }
    for (unsigned j = line_size; j < LINE_SIZE; ++j)
        out << "   ";

    out << "  \"";
    for (unsigned j = 0; j < line_size; ++j) {
        char c = *(char*)(arg + j);
        if (c >= ' ' && c <= '~')
            out << c;
        else
            out << '.';
    }
    out << "\"" << endl;
}

static void dump_arg(ADDRINT arg, unsigned size)
{
    for (unsigned j = 0; j < (size - 1) / LINE_SIZE + 1; ++j) {
        out << "  ";
        dump_arg_line_k(arg + j * LINE_SIZE,
                        min(LINE_SIZE, size - j * LINE_SIZE));
    }
}

VOID instrumentBPF(FunctionBreakpoint* f, ADDRINT pc, CONTEXT* ctx)
{

    // f->dump(out);

    if (g_call_stack->size() == 0) {
        cerr << "ERROR: shadow call stack is empty in instrumentBPF\n";
        exit(1);
    }
    FunctionInfo fi = g_call_stack->top();
    fi.print_ret    = true;

    string        caller_name = "";
    unsigned long caller_pc   = 0;
    if (fi.callsite_offset != -1) {
        caller_pc = fi.callsite - fi.callsite_offset;
        pair<unsigned, string> moduleid_name;
        bool ret = g_symbol_resolver.get_symbol_at(caller_pc, &moduleid_name);
        if (ret)
            caller_name =
                g_symbol_resolver.get_module_name(moduleid_name.first) + "!" +
                moduleid_name.second;
    }

    pair<unsigned, string> moduleid_name;
    bool    ret         = g_symbol_resolver.get_symbol_at(pc, &moduleid_name);
    int     module_id   = g_module_info->get_module_id(pc);
    ADDRINT module_base = g_module_info->get_img_base(module_id);
    string  module_name = g_symbol_resolver.get_module_name(module_id);

    out << "<bpf beg>  " << (ret ? moduleid_name.second : "unknown");
    out << " @ " << module_name << "+0x" << hex << pc - module_base;
    fi.function_name = (ret ? moduleid_name.second : "unknown");

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
    out << "  [ called from ";
    int     caller_module_id   = g_module_info->get_module_id(fi.callsite);
    ADDRINT caller_module_base = g_module_info->get_img_base(caller_module_id);
    string  caller_module_name =
        g_symbol_resolver.get_module_name(caller_module_id);

    if (caller_name != "")
        out << caller_name << "+" << dec << fi.callsite_offset << " @ "
            << caller_module_name << "+0x" << hex
            << fi.callsite - caller_module_base << " ]";
    else
        out << caller_module_name << "+0x" << hex
            << fi.callsite - caller_module_base << " ]";

    if (f->must_dump_callstack())
        print_callstack();
    g_call_stack->pop();

    if (f->must_skip()) {
        out << "  =>  [ skipped";
        if (f->must_change_ret_value()) {
            PIN_SetContextReg(ctx, REG_RAX, f->get_new_ret_value());
            out << " , force ret: 0x" << hex << f->get_new_ret_value();
        }
        out << " ]" << endl;

        out << "<bpf end>  " << fi.function_name << " -> 0x" << hex
            << PIN_GetContextReg(ctx, REG_RAX) << endl;
        PIN_SetContextReg(ctx, REG_INST_PTR, fi.ret_address);
        PIN_ExecuteAt(ctx);
    }

    if (f->must_change_ret_value()) {
        out << "  =>  [ force ret: 0x" << hex << f->get_new_ret_value() << " ]";
        fi.modify_ret_value = true;
        fi.ret_value        = f->get_new_ret_value();
        g_call_stack->push(fi);
    }

    unsigned dump_args = f->get_dump_args();
    if (dump_args > 0) {
        for (unsigned i = 0; i < f->get_num_args(); ++i) {
            ADDRINT arg_i = get_function_arg_k(ctx, i);
            if (is_mapped(arg_i)) {
                out << endl << "  dumping arg " << dec << i << endl;
                dump_arg(arg_i, dump_args);
            }
        }
    }

    g_call_stack->push(fi);
    out << endl;
}

static VOID dump_regs(CONTEXT* ctx)
{
    unsigned long res = 0;
    PIN_GetContextRegval(ctx, REG_RAX, (UINT8*)&res);
    out << "  ";
    out << "rax: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    PIN_GetContextRegval(ctx, REG_RBX, (UINT8*)&res);
    out << "rbx: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    PIN_GetContextRegval(ctx, REG_RCX, (UINT8*)&res);
    out << "rcx: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    out << endl;
    out << "  ";
    PIN_GetContextRegval(ctx, REG_RDX, (UINT8*)&res);
    out << "rdx: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    PIN_GetContextRegval(ctx, REG_RSI, (UINT8*)&res);
    out << "rsi: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    PIN_GetContextRegval(ctx, REG_RDI, (UINT8*)&res);
    out << "rdi: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    out << endl;
    out << "  ";
    PIN_GetContextRegval(ctx, REG_RSP, (UINT8*)&res);
    out << "rsp: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    PIN_GetContextRegval(ctx, REG_RBP, (UINT8*)&res);
    out << "rbp: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    PIN_GetContextRegval(ctx, REG_RIP, (UINT8*)&res);
    out << "rip: 0x" << setfill('0') << setw(16) << hex << res << "  ";
    out << endl;
}

static VOID dump_fp_regs(CONTEXT* ctx)
{
    double res = 0;
    PIN_GetContextRegval(ctx, REG_ST0, (UINT8*)&res);
    if (res == 0)
        return;
    out << "  ";
    out << "st0: " << fixed << setprecision(9) << res << "\t";
    PIN_GetContextRegval(ctx, REG_ST1, (UINT8*)&res);
    out << "st1: " << fixed << setprecision(9) << res << "\t";
    PIN_GetContextRegval(ctx, REG_ST2, (UINT8*)&res);
    out << "st2: " << fixed << setprecision(9) << res << "\t";
    PIN_GetContextRegval(ctx, REG_ST3, (UINT8*)&res);
    out << "st3: " << fixed << setprecision(9) << res << "\t";
    out << endl;
    out << "  ";
    PIN_GetContextRegval(ctx, REG_ST4, (UINT8*)&res);
    out << "st4: " << fixed << setprecision(9) << res << "\t";
    PIN_GetContextRegval(ctx, REG_ST5, (UINT8*)&res);
    out << "st5: " << fixed << setprecision(9) << res << "\t";
    PIN_GetContextRegval(ctx, REG_ST6, (UINT8*)&res);
    out << "st6: " << fixed << setprecision(9) << res << "\t";
    PIN_GetContextRegval(ctx, REG_ST7, (UINT8*)&res);
    out << "st7: " << fixed << setprecision(9) << res << "\t";
    out << endl;
}

static int bpx_if = 1;
int        instrumentBPXIf()
{
    // this is used to allow the re-execution of the instruction at which the
    // BPX breakpoint points, without recalling the instrumentation
    int res = bpx_if;
    bpx_if  = bpx_if == 0 ? 1 : 0;
    return res;
}

VOID instrumentBPXThen(InstructionBreakpoint* f, ADDRINT pc, CONTEXT* ctx)
{
    FunctionInfo  fi          = g_call_stack->top();
    string        caller_name = "";
    unsigned long caller_pc   = fi.function_addr;
    if (caller_pc != 0) {
        pair<unsigned, string> moduleid_name;
        bool ret = g_symbol_resolver.get_symbol_at(caller_pc, &moduleid_name);
        if (ret)
            caller_name =
                g_symbol_resolver.get_module_name(moduleid_name.first) + "!" +
                moduleid_name.second;
    }

    int     module_id   = g_module_info->get_module_id(pc);
    ADDRINT module_base = g_module_info->get_img_base(module_id);
    string  module_name = g_symbol_resolver.get_module_name(module_id);

    out << "<bpx beg> " << module_name << "+0x" << hex << pc - module_base;
    if (caller_name != "") {
        out << " ( " << caller_name << "+0x" << hex << pc - caller_pc << " )";
    }
    out << endl;
    dump_regs(ctx);
    dump_fp_regs(ctx);

    auto it_dump_reg = f->get_dump_reg_map().begin();
    while (it_dump_reg != f->get_dump_reg_map().end()) {
        out << endl;

        LEVEL_BASE::REG reg_id  = it_dump_reg->first;
        unsigned        reg_len = it_dump_reg->second;
        unsigned long   reg_val;
        PIN_GetContextRegval(ctx, reg_id, (UINT8*)&reg_val);
        if (is_mapped(reg_val)) {
            out << "  dumping *" << inverted_reg_map[reg_id] << endl;
            dump_arg(reg_val, reg_len);
        } else {
            out << "  " << inverted_reg_map[reg_id] << ": 0x" << hex << reg_val
                << endl;
        }
        it_dump_reg++;
    }

    auto it_set_map = f->get_set_map().begin();
    while (it_set_map != f->get_set_map().end()) {
        out << endl;

        LEVEL_BASE::REG reg_id  = it_set_map->first;
        unsigned long   reg_val = it_set_map->second;

        PIN_SetContextRegval(ctx, reg_id, (UINT8*)&reg_val);
        out << "  SET " << inverted_reg_map[reg_id] << " <- 0x" << hex
            << reg_val << endl;
        it_set_map++;
    }
    auto it_set_fp_map = f->get_set_fp_map().begin();
    while (it_set_fp_map != f->get_set_fp_map().end()) {
        out << endl;

        LEVEL_BASE::REG reg_id  = it_set_fp_map->first;
        double          reg_val = it_set_fp_map->second;

        PIN_SetContextRegval(ctx, reg_id, (UINT8*)&reg_val);
        out << "  SET " << inverted_reg_map[reg_id] << " <- " << reg_val
            << endl;
        it_set_fp_map++;
    }

    out << "<bpx end>" << endl;
    PIN_ExecuteAt(ctx);
}
