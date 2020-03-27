#include <fstream>
#include <iostream>
#include <stack>
#include "pin.H"
#include "function_info.hpp"
#include "instrument.hpp"
#include "option_manager.hpp"
#include "symbol_resolver.hpp"
#include "module_info.hpp"

using namespace std;

SymbolResolver      g_symbol_resolver;
OptionManager*      g_option_manager;
ModuleInfo*         g_module_info;
stack<FunctionInfo> g_call_stack;

KNOB<string> KnobPrintSymbols(KNOB_MODE_WRITEONCE, "pintool", "print_symb", "",
                              "Print symbols");
KNOB<string> KnobBpf(KNOB_MODE_APPEND, "pintool", "bpf", "",
                     "Specify function breakpoint");

INT32 Usage()
{
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID Trace(TRACE trace, VOID* v)
{
    BBL first_block       = TRACE_BblHead(trace);
    INS first_instruction = BBL_InsHead(first_block);

    // I'm assuming that the first instruction of all calls appears
    // as first instructions in a Trace. Is it correct?
    ADDRINT pc = INS_Address(first_instruction);
    auto    f  = g_option_manager->BPF_must_instrument(pc);
    if (f != NULL) {
        INS_InsertCall(first_instruction, IPOINT_BEFORE, (AFUNPTR)instrumentBPF,
                       IARG_ADDRINT, (ADDRINT)f, IARG_ADDRINT, pc, IARG_CONTEXT,
                       IARG_END);
    }

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsCall(ins)) {
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                               (AFUNPTR)InstrumentCallAfter, IARG_INST_PTR,
                               IARG_BRANCH_TARGET_ADDR, IARG_RETURN_IP,
                               IARG_END);
            }
            if (INS_IsRet(ins))
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InstrumentRet,
                               IARG_REG_REFERENCE, REG_RAX, IARG_END);
        }
    }
}

VOID ImageLoad(IMG img, VOID* v)
{
    auto module_id        = IMG_Id(img);
    auto module_name_full = IMG_Name(img);
    g_module_info->add_img(module_id, IMG_LowAddress(img));
    g_symbol_resolver.add_module(module_id, module_name_full);

    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        g_symbol_resolver.add_symbol(SYM_Address(sym), module_id,
                                     (string&)SYM_Name(sym));
    }

    g_symbol_resolver.print_symbols(cerr, module_id);
}

VOID Fini(INT32 code, VOID* v)
{
    delete g_option_manager;
    delete g_module_info;
}

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
        return Usage();
    PIN_InitSymbols();

    g_option_manager = new OptionManager(KnobPrintSymbols, KnobBpf);
    g_module_info    = new ModuleInfo();

    cerr.setf(std::ios::unitbuf);

    FunctionInfo fi;
    fi.function_addr = 0;
    g_call_stack.push(fi);

    TRACE_AddInstrumentFunction(Trace, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
