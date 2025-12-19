#pragma once
#include <ntifs.h>
#include "structures.h"

#include "memory.h"
#include "paging.h"
namespace cheat
{
	bool read_kernel(void* ubuffer, unsigned long long size, void* address)
	{
		if (!ubuffer || !size || !address)
			return false;


		crt::memcpy(ubuffer, address, size);

		return true;
	}

	bool read_physical(void* ubuffer, unsigned long long size, void* address, void* pid, unsigned long long cr3)
	{
		if (!ubuffer || !size || !address || !pid)
			return false;
		//unsigned long long cr3 = paging::get_cr3_kestackattach(pid);
		if (!cr3)
			return false;
		unsigned long long physical = paging::vtop((unsigned long long)address, cr3);
		if (!physical)
			return false;
		memory::copy_physical(ubuffer, physical, size);
		return true;
	}

	bool write_memory(void* value, void* address, void* pid, unsigned long long size, unsigned long long cr3)
	{
		if (!value || !address || !pid || !size)
			return false;

		//unsigned long long cr3 = paging::get_cr3_kestackattach(pid);

		if (!cr3)
			return false;

		unsigned long long physical = paging::vtop((unsigned long long)address, cr3);

		if (!physical)
			return false;

		void* va = memory::map_io_region(physical, size);
		if (!va)
			return false;



		crt::memcpy(va, value, size);

		func_ptrs.MmUnmapIoSpace(va, size);

		return true;

	}

	void* get_base(void* pid)
	{
		if (!pid)
			return 0;

		PEPROCESS eprocess = 0;
		func_ptrs.PsLookupProcessByProcessId(pid, &eprocess);
		void* ret = func_ptrs.PsGetProcessSectionBaseAddress(eprocess);
		if (!ret) {
			func_ptrs.ObDereferenceObject(eprocess);
			return 0;
		}

		func_ptrs.ObDereferenceObject(eprocess);
		return ret;


	}
}