#pragma once

#include <ntifs.h>
#include "ntos.h"
#include "structures.h"
#include <intrin.h>
#include "ia32.h"
#include "skcrypt.h"
#include "resolver.h"
namespace tools
{
	void* get_kmodule(LPCWSTR module_name) {
		const char* name = "PsLoadedModuleList";

		PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(resolver::get_system_routine(name));
		if (!module_list)
			return nullptr;
		for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink) {
			LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			UNICODE_STRING name;
			func_ptrs.RtlInitUnicodeString(&name, module_name);
			if (func_ptrs.RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE)) {
				return entry->DllBase;
			}
		}
		return nullptr;
	}

	void* ptov(unsigned long long address)
	{
		if (!address)
			return nullptr;

		PHYSICAL_ADDRESS phys;
		phys.QuadPart = address;
		return func_ptrs.MmGetVirtualForPhysical(phys);
	}

	template <typename t>
	t read_object(void* object_pointer, std::uintptr_t offset)
	{
		if (!object_pointer)
			return t{};
		
		return *reinterpret_cast<t*>(reinterpret_cast<std::uintptr_t>(object_pointer) + offset);
	}

	template <typename t>
	void write_object(void* object_pointer, std::uintptr_t offset, t value) //gangsta
	{
		if (!object_pointer)
			return;

		*reinterpret_cast<t*>(reinterpret_cast<std::uintptr_t>(object_pointer) + offset) = value;
	}
	//can read / write usermode memory if attached / in context of usermode program
	template <typename t>
	t read_kmem(std::uintptr_t offset)
	{
		return *reinterpret_cast<t*>(offset);
	}

	template <typename t>
	void read_kmem(std::uintptr_t offset, t value)
	{
		*reinterpret_cast<t*>(offset) = value;
	}

	template <typename t>
	t read_kmem_idx(std::uintptr_t base, size_t index) {
		return *reinterpret_cast<t*>(base + (index * sizeof(t)));
	}

	template <typename t>
	void write_kmem_idx(std::uintptr_t base, size_t index, t value) {
		*reinterpret_cast<t*>(base + (index * sizeof(t))) = value;
	}

}