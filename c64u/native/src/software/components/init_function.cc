/*
 * init_function.cc
 *
 *  Created on: Mar 12, 2015
 *      Author: Gideon
 */

#include "init_function.h"
#include <stdio.h>

#if defined(C64U_BOOT_TRACE) && C64U_BOOT_TRACE
#include <stdint.h>
#include "c64u_boot_trace.h"
#define C64U_TRACE_STAGE(stage, detail) c64u_boot_stage((stage), (detail))
#else
#define C64U_TRACE_STAGE(stage, detail) do { } while (0)
#endif
static IndexedList<InitFunction *> *getInitFunctionList(void) {
	static IndexedList<InitFunction *> initFunctions(24, 0);
	return &initFunctions;
}

InitFunction::InitFunction(const char *name, initFunction_t func, void *obj, void *prm, int ord) {
	this->name = name;
    function = func;
	object = obj;
	param = prm;
	ordering = ord;

	getInitFunctionList()->append(this);
}

InitFunction::~InitFunction() {

}

void InitFunction::executeAll() {
    getInitFunctionList()->sort(InitFunction::compare);
    int elements = getInitFunctionList()->get_elements();
	for (int i=0; i < elements; i++) {
	    InitFunction *func = (*getInitFunctionList())[i];
        C64U_TRACE_STAGE(0x1f, (unsigned)(uintptr_t)func->function);
        printf("----> Initializing %s (%d)...\n", func->name, func->ordering);
        C64U_TRACE_STAGE(0x20, (unsigned)(uintptr_t)func->function);
		func->function(func->object, func->param);
        C64U_TRACE_STAGE(0x21, (unsigned)(uintptr_t)func->function);
	}
	printf("---> All Init functions called.\n");
}

int InitFunction::compare(IndexedList<InitFunction *> *list, int a, int b)
{
    InitFunction *obj_a = (*list)[a];
    InitFunction *obj_b = (*list)[b];

    if(!obj_b)
        return 1;
    if(!obj_a)
        return -1;

    return obj_a->ordering - obj_b->ordering;
}

extern "C" {
	void execute_init_functions(void) {
		InitFunction::executeAll();
	}
}
