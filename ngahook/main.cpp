#include "comms.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_path)
{
    if (!resolver::setup())
    {
        return nt_unsuccessful;
    }
    if (!hooks::setup_hooks(&comms::hook_handler, (void**)&comms::original_pointer))
    {
        return nt_unsuccessful;
    }
    return nt_success;
}