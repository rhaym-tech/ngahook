#pragma once
#include "structures.h"
#include "crt.h"
#include "skcrypt.h"
extern "C" std::uintptr_t get_nt_base();
std::uintptr_t m_nt_base = 0;

namespace resolver
{
	unsigned char* get_system_routine(const char* export_name) {
		auto dos_header{ reinterpret_cast<dos_header_t*> (m_nt_base) };
		auto nt_headers{ reinterpret_cast<nt_headers_t*> (m_nt_base + dos_header->m_lfanew) };
		if (!dos_header->is_valid()
			|| !nt_headers->is_valid())
			return {};

		auto exp_dir{ nt_headers->m_export_table.as_rva< export_directory_t* >(m_nt_base) };
		if (!exp_dir->m_address_of_functions
			|| !exp_dir->m_address_of_names
			|| !exp_dir->m_address_of_names_ordinals)
			return {};

		auto name{ reinterpret_cast<std::int32_t*> (m_nt_base + exp_dir->m_address_of_names) };
		auto func{ reinterpret_cast<std::int32_t*> (m_nt_base + exp_dir->m_address_of_functions) };
		auto ords{ reinterpret_cast<std::int16_t*> (m_nt_base + exp_dir->m_address_of_names_ordinals) };

		for (std::int32_t i{}; i < exp_dir->m_number_of_names; i++) {
			auto cur_name{ m_nt_base + name[i] };
			auto cur_func{ m_nt_base + func[ords[i]] };
			if (!cur_name
				|| !cur_func)
				continue;

			if (crt::strcmp(export_name, reinterpret_cast<char*>(cur_name)) == 0)
				return reinterpret_cast<unsigned char*>(cur_func);
		}
		return {};
	}

	bool setup()
	{
		m_nt_base = get_nt_base();
		if (!m_nt_base)
			return false;
		func_ptrs.RtlInitUnicodeString = (RtlInitUnicodeString_t)get_system_routine(skCrypt("RtlInitUnicodeString"));
		func_ptrs.ExGetPreviousMode = (PEX_GET_PREVIOUS_MODE)get_system_routine(skCrypt("ExGetPreviousMode"));
		func_ptrs.KeGetCurrentIrql = (KeGetCurrentIrql_t)get_system_routine(skCrypt("KeGetCurrentIrql"));
		func_ptrs.IoGetCurrentIrpStackLocation = (IoGetCurrentIrpStackLocation_t)get_system_routine(skCrypt("IoGetCurrentIrpStackLocation"));
		func_ptrs.KeGetCurrentProcessorIndex = (KeGetCurrentProcessorIndex_t)get_system_routine(skCrypt("KeGetCurrentProcessorIndex"));
		func_ptrs.MmAllocateContiguousMemory = (MmAllocateContiguousMemory_t)get_system_routine(skCrypt("MmAllocateContiguousMemory"));
		func_ptrs.MmFreeContiguousMemory = (MmFreeContiguousMemory_t)get_system_routine(skCrypt("MmFreeContiguousMemory"));
		func_ptrs.MmCopyMemory = (MmCopyMemory_t)get_system_routine(skCrypt("MmCopyMemory"));
		func_ptrs.IofCompleteRequest = (IofCompleteRequest_t)get_system_routine(skCrypt("IofCompleteRequest"));
		func_ptrs.PsLookupProcessByProcessId = (PsLookupProcessByProcessId_t)get_system_routine(skCrypt("PsLookupProcessByProcessId"));
		func_ptrs.KeStackAttachProcess = (KeStackAttachProcess_t)get_system_routine(skCrypt("KeStackAttachProcess"));
		func_ptrs.KeUnstackDetachProcess = (KeUnstackDetachProcess_t)get_system_routine(skCrypt("KeUnstackDetachProcess"));
		func_ptrs.ObfDereferenceObject = (ObfDereferenceObject_t)get_system_routine(skCrypt("ObfDereferenceObject"));
		func_ptrs.IoAllocateMdl = (IoAllocateMdl_t)get_system_routine(skCrypt("IoAllocateMdl"));
		func_ptrs.MmProbeAndLockPages = (MmProbeAndLockPages_t)get_system_routine(skCrypt("MmProbeAndLockPages"));
		func_ptrs.MmGetMdlPfnArray = (MmGetMdlPfnArray_t)get_system_routine(skCrypt("MmGetMdlPfnArray"));
		func_ptrs.MmUnlockPages = (MmUnlockPages_t)get_system_routine(skCrypt("MmUnlockPages"));
		func_ptrs.IoFreeMdl = (IoFreeMdl_t)get_system_routine(skCrypt("IoFreeMdl"));
		func_ptrs.RtlEqualUnicodeString = (RtlEqualUnicodeString_t)get_system_routine(skCrypt("RtlEqualUnicodeString"));
		func_ptrs.PsGetProcessSectionBaseAddress = (PsGetProcessSectionBaseAddress_t)get_system_routine(skCrypt("PsGetProcessSectionBaseAddress"));
		func_ptrs.MmGetPhysicalMemoryRanges = (MmGetPhysicalMemoryRanges_t)get_system_routine(skCrypt("MmGetPhysicalMemoryRanges"));
		func_ptrs.ExFreePoolWithTag = (ExFreePoolWithTag_t)get_system_routine(skCrypt("ExFreePoolWithTag"));
		func_ptrs.MmMapIoSpace = (MmMapIoSpace_t)get_system_routine(skCrypt("MmMapIoSpace"));
		func_ptrs.MmMapIoSpaceEx = (MmMapIoSpaceEx_t)get_system_routine(skCrypt("MmMapIoSpaceEx"));
		func_ptrs.MmGetPhysicalAddress = (MmGetPhysicalAddress_t)get_system_routine(skCrypt("MmGetPhysicalAddress"));
		func_ptrs.MmGetVirtualForPhysical = (MmGetVirtualForPhysical_t)get_system_routine(skCrypt("MmGetVirtualForPhysical"));
		func_ptrs.MmUnmapIoSpace = (MmUnmapIoSpace_t)get_system_routine(skCrypt("MmUnmapIoSpace"));
		func_ptrs.KfRaiseIrql = (KfRaiseIrql_t)get_system_routine(skCrypt("KfRaiseIrql"));
		func_ptrs.KeLowerIrql = (KeLowerIrql_t)get_system_routine(skCrypt("KeLowerIrql"));
		func_ptrs.IoGetDeviceObjectPointer = (IoGetDeviceObjectPointer_t)get_system_routine(skCrypt("IoGetDeviceObjectPointer"));
		func_ptrs.MmProtectMdlSystemAddress = (PMM_PROTECT_MDL_SYSTEM_ADDRESS)get_system_routine(skCrypt("MmProtectMdlSystemAddress"));
		func_ptrs.MmMapLockedPagesSpecifyCache = (PMM_MAP_LOCKED_PAGES_SPECIFY_CACHE)get_system_routine(skCrypt("MmMapLockedPagesSpecifyCache"));
		func_ptrs.MmUnmapLockedPages = (PMM_UNMAP_LOCKED_PAGES)get_system_routine(skCrypt("MmUnmapLockedPages"));

		return true;
	}
}