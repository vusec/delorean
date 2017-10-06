#define KSYM_TABLE 1

#include <ksym.h>

void* ksym_import(const char* name, void **sym)
{
    if (*sym) {
        return *sym;
    }
    return ksym_init(name, sym);
}

void* ksym_init(const char* name, void **sym)
{
    *sym = (void*) kallsyms_lookup_name(name);
    BUG_ON(!(*sym));

    return *sym;
}


