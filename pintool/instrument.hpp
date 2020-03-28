#ifndef INSTRUMENT_H
#define INSTRUMENT_H

#include "pin.H"
#include "function_breakpoint.hpp"
#include "instruction_breakpoint.hpp"

VOID InstrumentCallAfter(ADDRINT call_pc, ADDRINT dest_pc, ADDRINT ret_pc);
VOID InstrumentRet(ADDRINT* rax);

VOID instrumentBPF(FunctionBreakpoint* f, ADDRINT pc, CONTEXT* ctx);
VOID instrumentBPX(InstructionBreakpoint* f, ADDRINT pc, CONTEXT* ctx);

#endif