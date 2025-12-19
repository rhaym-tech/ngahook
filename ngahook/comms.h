#pragma once
#include "hooks.h"
#include "cheat.h"
#include "paging.h"
typedef __int64(__fastcall* NtUserInitializeInputDeviceInjection_t)(INT64);

typedef struct cmd_t
{
	unsigned long long magic = 0;

	enum operation_e
	{
		read = 0x1,
		write = 0x2,
		base = 0x3,
		read_kmem = 0x4,
		get_cr3 = 0x5
	};

	int operation;

	void* user_buffer = nullptr;
	void* address = nullptr;
	void* pid = nullptr;
	unsigned long long size = 0;
	void* write_value = nullptr;
	void* base_return = nullptr;
	unsigned long long cr3_return = 0;
	unsigned long long cr3 = 0;
};

namespace comms
{
	
	NtUserInitializeInputDeviceInjection_t original_pointer = nullptr;
	INT64 hook_handler(INT64 a1)
	{
		if (func_ptrs.ExGetPreviousMode() != UserMode)
		{
			return original_pointer(a1);
		}

		if (!a1)
			return original_pointer(a1);

		if (!MmIsAddressValid((void*)a1))
			return original_pointer(a1);

		cmd_t* cmd = (cmd_t*)a1;
		if (!cmd)
			return original_pointer(a1);

		if (cmd->magic != 0x77FF77FF)
		{
			return original_pointer(a1);
		}

		switch (cmd->operation)
		{
		case cmd_t::read:
		{
			cheat::read_physical(cmd->user_buffer, cmd->size, cmd->address, cmd->pid, cmd->cr3);
			break;
		}
		case cmd_t::write:
		{
			cheat::write_memory(cmd->write_value, cmd->address, cmd->pid, cmd->size, cmd->cr3);
			break;
		}
		case cmd_t::base:
		{
			cmd->base_return = cheat::get_base(cmd->pid);
			break;
		}
		case cmd_t::read_kmem:
		{
			cheat::read_kernel(cmd->user_buffer, cmd->size, cmd->address);
			break;
		}
		case cmd_t::get_cr3:
		{
			ULONG32 pid_value = (ULONG32)(ULONG_PTR)cmd->pid;
			cmd->cr3_return = paging::find_process_cr3(pid_value);
			break;
		}
		default:
		{
			break;
		}
		}

		return original_pointer(a1);
	}
}
