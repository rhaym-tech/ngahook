#pragma once
#include "tools.h"


namespace memory
{
	void* map_io_region(unsigned long long address, unsigned long long size)
	{
		PHYSICAL_ADDRESS phys;
		phys.QuadPart = (unsigned long long)address;
		return func_ptrs.MmMapIoSpace(phys, size, MmCached);
	}

	void* map_io_region_ex(void* address, unsigned long long size, unsigned long long protect)
	{
		PHYSICAL_ADDRESS phys;
		phys.QuadPart = (unsigned long long)address;
		return func_ptrs.MmMapIoSpaceEx(phys, size, protect);
	}

	unsigned long long copy_memory_physical(unsigned long long destination, unsigned long long source, unsigned long long size) {
		if (!destination || !source || !size) {
			return STATUS_INVALID_PARAMETER;
		}

		MM_COPY_ADDRESS copy_address = { 0 };
		copy_address.PhysicalAddress.QuadPart = source;
		unsigned long long out_size = 0;

		NTSTATUS status = func_ptrs.MmCopyMemory((void*)destination, copy_address, size, MM_COPY_MEMORY_PHYSICAL, &out_size);

		if (NT_SUCCESS(status) && out_size != size) {
			return STATUS_PARTIAL_COPY;
		}
		return status;
	}

	bool copy_physical(void* dst, unsigned long long src, unsigned long long size)
	{
		if (!dst || !src || !size)
			return false;

		MM_COPY_ADDRESS copy;
		copy.PhysicalAddress.QuadPart = src;
		unsigned long long  sz = 0;
		func_ptrs.MmCopyMemory(dst, copy, size, MM_COPY_MEMORY_PHYSICAL, &sz);
		return true;
	}

}