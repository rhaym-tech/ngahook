#pragma once
#include "tools.h"


namespace hooks
{
	bool setup_hooks(void* hook_handler, void** original)
	{
		if (!hook_handler || !original)
			return false;

		void* module = tools::get_kmodule(L"win32k.sys");
		if (!module)
			return false;

		unsigned long long offset = 0X0066AB8;

		void** function_pointer = (void**)((unsigned char*)module + offset);
		if (!function_pointer)
			return false;

		*original = *function_pointer;

		PMDL mdl = func_ptrs.IoAllocateMdl(function_pointer, sizeof(void*), false, false, 0);
		if (!mdl)
			return false;

		func_ptrs.MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		func_ptrs.MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
		 
		void* mapped = func_ptrs.MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, false, NormalPagePriority);

		InterlockedExchangePointer((void**)mapped, hook_handler);
		func_ptrs.MmUnmapLockedPages(mapped, mdl);
		func_ptrs.MmUnlockPages(mdl);
		func_ptrs.IoFreeMdl(mdl);

		return true;
	}
}