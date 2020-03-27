#ifndef INSTRUMENT_H
#define INSTRUMENT_H

#include "pin.H"
#include "function_breakpoint.hpp"

void instrumentBPF(FunctionBreakpoint* f, ADDRINT pc, CONTEXT* ctx);

#endif