#pragma once
#include "memory.h"
#include "cheat.h"

namespace paging
{
	unsigned long long get_pml4_base(unsigned long long cr3)
	{
		return cr3 & PAGE_MASK_4KB;
	}


	//unsigned long long vtop(unsigned long long va, unsigned long long cr3)
	//{
	//	if (!va || !cr3)
	//		return 0;

	//	unsigned long long pml4_idx = (va >> 39) & 0x1FF;
	//	unsigned long long pdpt_idx = (va >> 30) & 0x1FF;
	//	unsigned long long pd_idx = (va >> 21) & 0x1FF;
	//	unsigned long long pt_idx = (va >> 12) & 0x1FF;
	//	unsigned long long page = va & 0xFFF;

	//	unsigned long long pml4_base = paging::get_pml4_base(cr3);
	//	unsigned long long pml4e_raw = pml4_base + (pml4_idx * 8);
	//	unsigned long long pml4e = 0;
	//	void* vpml4 = tools::ptov(pml4e_raw);
	//	crt::memcpy(&pml4e, vpml4, sizeof(unsigned long long));

	//	if (!(pml4e & 1))
	//		return 0;

	//	unsigned long long pdpt_base = pml4e & PAGE_MASK_4KB;
	//	unsigned long long pdpte_raw = pdpt_base + (pdpt_idx * 8);
	//	unsigned long long pdpte = 0;
	//	void* vpdpt = tools::ptov(pdpte_raw);
	//	crt::memcpy(&pdpte, vpdpt, sizeof(unsigned long long));

	//	if (!(pdpte & 1))
	//		return 0;

	//	if (pdpte & (1ULL << 7))
	//	{
	//		unsigned long long physical = (pdpte & PAGE_MASK_1GB) | (va & PAGE_OFFSET_1GB);
	//		return physical;
	//	}


	//	unsigned long long pd_base = pdpte & PAGE_MASK_4KB;
	//	unsigned long long pde_raw = pd_base + (pd_idx * 8);
	//	unsigned long long pde = 0;
	//	void* vpd = tools::ptov(pde_raw);
	//	crt::memcpy(&pde, vpd, sizeof(unsigned long long));

	//	if (!(pde & 1))
	//		return 0;

	//	if (pde & (1ULL << 7))
	//	{
	//		unsigned long long physical = (pde & PAGE_MASK_2MB) | (va & PAGE_OFFSET_2MB);
	//		return physical;
	//	}


	//	unsigned long long pt_base = pde & PAGE_MASK_4KB;
	//	unsigned long long pte_raw = pt_base + (pt_idx * 8);
	//	unsigned long long pte = 0;
	//	void* vpte = tools::ptov(pte_raw);
	//	crt::memcpy(&pte, vpte, sizeof(unsigned long long));

	//	if (!(pte & 1))
	//		return 0;
	//	unsigned long long physical = (pte & PAGE_MASK_4KB) | page;
	//	if (!physical)
	//	{
	//		return 0;
	//	}
	//	return physical;

	//}

	unsigned long long vtop(unsigned long long va, unsigned long long cr3)
	{
		if (!va || !cr3)
			return 0;
		unsigned long long pml4_idx = (va >> 39) & 0x1FF;
		unsigned long long pdpt_idx = (va >> 30) & 0x1FF;
		unsigned long long pd_idx = (va >> 21) & 0x1FF;
		unsigned long long pt_idx = (va >> 12) & 0x1FF;
		unsigned long long page = va & 0xFFF;
		unsigned long long pml4_base = get_pml4_base(cr3);
		unsigned long long pml4e_raw = pml4_base + (pml4_idx * 8);
		unsigned long long pml4e = 0;
		memory::copy_physical(&pml4e, pml4e_raw, sizeof(unsigned long long));
		if (!(pml4e & 1))
			return 0;
		unsigned long long pdpt_base = pml4e & PAGE_MASK_4KB;
		unsigned long long pdpte_raw = pdpt_base + (pdpt_idx * 8);
		unsigned long long pdpte = 0;
		memory::copy_physical(&pdpte, pdpte_raw, sizeof(unsigned long long));
		if (!(pdpte & 1))
			return 0;
		if (pdpte & (1ULL << 7))
		{
			unsigned long long physical = (pdpte & PAGE_MASK_1GB) | (va & PAGE_OFFSET_1GB);
			return physical;
		}
		unsigned long long pd_base = pdpte & PAGE_MASK_4KB;
		unsigned long long pde_raw = pd_base + (pd_idx * 8);
		unsigned long long pde = 0;
		memory::copy_physical(&pde, pde_raw, sizeof(unsigned long long));
		if (!(pde & 1))
			return 0;
		if (pde & (1ULL << 7))
		{
			unsigned long long physical = (pde & PAGE_MASK_2MB) | (va & PAGE_OFFSET_2MB);
			return physical;
		}
		unsigned long long pt_base = pde & PAGE_MASK_4KB;
		unsigned long long pte_raw = pt_base + (pt_idx * 8);
		unsigned long long pte = 0;
		memory::copy_physical(&pte, pte_raw, sizeof(unsigned long long));
		if (!(pte & 1))
			return 0;
		unsigned long long physical = (pte & PAGE_MASK_4KB) | (va & PAGE_OFFSET_4KB);
		return physical;
	}


	ULONG_PTR* get_pte_address(ULONG_PTR va, ULONG_PTR cr3)
	{
		if (!va || !cr3)
			return NULL;
		ULONG_PTR pml4_index = (va >> 39) & 0x1FF;
		ULONG_PTR pdpt_index = (va >> 30) & 0x1FF;
		ULONG_PTR pd_index = (va >> 21) & 0x1FF;
		ULONG_PTR pt_index = (va >> 12) & 0x1FF;
		ULONG_PTR pml4_raw = get_pml4_base(cr3);
		ULONG_PTR* pml4 = (ULONG_PTR*)tools::ptov(pml4_raw);
		ULONG_PTR pml4e = pml4[pml4_index];
		if (!(pml4e & 1))
		{
			return NULL;
		}
		ULONG_PTR pdpt_raw = pml4e & PAGE_MASK_4KB;
		ULONG_PTR* pdpt = (ULONG_PTR*)tools::ptov(pdpt_raw);
		ULONG_PTR pdpte = pdpt[pdpt_index];
		if (!(pdpte & 1))
		{
			return NULL;
		}
		ULONG_PTR pd_raw = pdpte & PAGE_MASK_4KB;
		ULONG_PTR* pd = (ULONG_PTR*)tools::ptov(pd_raw);
		ULONG_PTR pde = pd[pd_index];
		if (!(pde & 1))
		{
			return NULL;
		}
		ULONG_PTR pt_raw = pde & PAGE_MASK_4KB;
		ULONG_PTR* pt = (ULONG_PTR*)tools::ptov(pt_raw);
		return &pt[pt_index];
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

	ULONG64 find_process_cr3(ULONG32 process_id) {

		if (!process_id) {
			return 0;
		}
		ULONG64 process_base = (ULONG64)get_base((void*)process_id);
		if (!process_base) {
			return 0;
		}
		PPHYSICAL_MEMORY_RANGE ranges = func_ptrs.MmGetPhysicalMemoryRanges();
		if (!ranges) {
			return 0;
		}
		for (ULONG32 idx = 0;; idx++) {
			PPHYSICAL_MEMORY_RANGE element = &ranges[idx];
			if (!element->BaseAddress.QuadPart && !element->NumberOfBytes.QuadPart) {
				break;
			}
			if (!element->BaseAddress.QuadPart || !element->NumberOfBytes.QuadPart) {
				continue;
			}
			ULONG64 physical = element->BaseAddress.QuadPart;
			ULONG64 num_pages = element->NumberOfBytes.QuadPart / PAGE_SIZE;
			for (ULONG64 jdx = 0; jdx < num_pages; jdx++, physical += PAGE_SIZE) {
				ULONG64 translated_address = paging::vtop(process_base, physical);
				if (!translated_address) {
					continue;
				}
				USHORT mz_magic = 0;
				NTSTATUS status = memory::copy_memory_physical((ULONG64)&mz_magic, translated_address, sizeof(USHORT));
				if (NT_SUCCESS(status) && mz_magic == 0x5A4D) {
					func_ptrs.ExFreePool(ranges);
					return physical;
				}
			}
		}
		func_ptrs.ExFreePool(ranges);
		return 0;
	}

}
