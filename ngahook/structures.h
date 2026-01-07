#pragma once
#include <ntifs.h>
#include <cstdint>

#define PAGE_MASK_4KB    0x000FFFFFFFFFF000ULL  
#define PAGE_MASK_2MB    0x000FFFFFFFE00000ULL  
#define PAGE_MASK_1GB    0x000FFFFFC0000000ULL  

#define PAGE_OFFSET_4KB  0x0000000000000FFFULL 
#define PAGE_OFFSET_2MB  0x00000000001FFFFFULL  
#define PAGE_OFFSET_1GB  0x000000003FFFFFFFULL  

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef enum ntstatus_e
{
    nt_success = 0x00000000,
    nt_unsuccessful = 0xC0000001L,
    nt_wait_0 = 0x00000000,
    nt_wait_1 = 0x00000001,
    nt_wait_2 = 0x00000002,
    nt_wait_3 = 0x00000003,
    nt_wait_63 = 0x0000003F,
    nt_abandoned_wait_0 = 0x00000080,
    nt_abandoned_wait_63 = 0x000000BF,
    nt_user_apc = 0x000000C0,
    nt_kernel_apc = 0x00000100,
    nt_alerted = 0x00000101,
    nt_timeout = 0x00000102,
    nt_pending = 0x00000103,
    nt_reparse = 0x00000104,
    nt_more_entries = 0x00000105,
    nt_not_all_assigned = 0x00000106,
    nt_some_not_mapped = 0x00000107,
    nt_oplock_break_in_progress = 0x00000108,
    nt_volume_mounted = 0x00000109,
    nt_rxact_committed = 0x0000010A,
    nt_notify_cleanup = 0x0000010B,
    nt_notify_enum_dir = 0x0000010C,
    nt_no_quotas_for_account = 0x0000010D,
    nt_primary_transport_connect_failed = 0x0000010E,
    nt_page_fault_transition = 0x00000110,
    nt_page_fault_copy_on_write = 0x00000111,
    nt_page_fault_guard_page = 0x00000112,
    nt_page_fault_paging_file = 0x00000113,
    nt_cache_page_locked = 0x00000114,
    nt_crash_dump = 0x00000116,
    nt_reparse_object = 0x00000118,
    nt_fsfilter_op_completed_successfully = 0x00000126,
    nt_object_name_exists = 0x40000000,
    nt_thread_was_suspended = 0x40000001,
    nt_working_set_limit_range = 0x40000002,
    nt_image_not_at_base = 0x40000003,
    nt_rxact_state_created = 0x40000004,
    nt_segment_notification = 0x40000005,
    nt_local_user_session_key = 0x40000006,
    nt_bad_current_directory = 0x40000007,
    nt_serial_more_writes = 0x40000008,
    nt_registry_recovered = 0x40000009,
    nt_ft_read_recovery_from_backup = 0x4000000A,
    nt_ft_write_recovery = 0x4000000B,
    nt_serial_counter_timeout = 0x4000000C,
    nt_null_ls_reply_received = 0x4000000D,
    nt_ls_reply_received = 0x4000000E,
    nt_ds_shutting_down = 0x4000000F,
    nt_wow_assigned_as_default_desktop = 0x40000010,
    nt_wow_wxp_assigned_as_default_desktop = 0x40000011,
    nt_wow_sleeping = 0x40000012,
    nt_ds_name_not_unique = 0x40020056,
    nt_ds_different_security_ids = 0x4002000E,
    nt_warning_other = 0x40000013,
    nt_object_name_collision = 0x40000018,
    nt_port_disconnected = 0xC0000037,
    nt_invalid_handle = 0xC0000008,
    nt_invalid_parameter = 0xC000000D,
    nt_no_such_device = 0xC000000E,
    nt_no_such_file = 0xC000000F,
    nt_invalid_device_request = 0xC0000010,
    nt_end_of_file = 0xC0000011,
    nt_wrong_volume = 0xC0000012,
    nt_no_media_in_device = 0xC0000013,
    nt_nonexistent_sector = 0xC0000015,
    nt_status_access_denied = 0xC0000022,
    nt_buffer_too_small = 0xC0000023,
    nt_object_type_mismatch = 0xC0000024,
    nt_object_name_invalid = 0xC0000033,
    nt_object_name_not_found = 0xC0000034,
    nt_object_name_collision2 = 0xC0000035,
    nt_port_disconnected2 = 0xC0000037,
    nt_device_already_attached = 0xC000003A,
    nt_invalid_page_protection = 0xC0000045,
    nt_mutant_not_owned = 0xC0000046,
    nt_thread_not_in_process = 0xC0000047,
    nt_port_closed = 0xC0000049,
    nt_invalid_object = 0xC000004C,
    nt_invalid_port_attributes = 0xC000004E,
    nt_port_message_too_long = 0xC000004F,
    nt_invalid_parameter_mix = 0xC0000030
} ntstatus_e;

typedef NTSTATUS(*MmCopyMemory_t)(
    PVOID TargetAddress,
    MM_COPY_ADDRESS SourceAddress,
    SIZE_T NumberOfBytes,
    ULONG Flags,
    PSIZE_T NumberOfBytesTransferred
    );

typedef struct _MM_COPY_ADDRESS_T {
    union {
        PVOID VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS_T, * PMM_COPY_ADDRESS;


typedef VOID(*IofCompleteRequest_t)(PIRP Irp, CCHAR PriorityBoost);
typedef NTSTATUS(*PsLookupProcessByProcessId_t)(HANDLE ProcessId, PEPROCESS* Process);
typedef VOID(*KeStackAttachProcess_t)(PEPROCESS Process, PKAPC_STATE ApcState);
typedef VOID(*KeUnstackDetachProcess_t)(PKAPC_STATE ApcState);
typedef VOID(*ObfDereferenceObject_t)(PVOID Object);
typedef PMDL(*IoAllocateMdl_t)(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
typedef VOID(*MmProbeAndLockPages_t)(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation);
typedef PPFN_NUMBER(*MmGetMdlPfnArray_t)(PMDL Mdl);
typedef VOID(*MmUnlockPages_t)(PMDL MemoryDescriptorList);
typedef VOID(*IoFreeMdl_t)(PMDL Mdl);
typedef BOOLEAN(*RtlEqualUnicodeString_t)(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSensitive);
typedef PVOID(*PsGetProcessSectionBaseAddress_t)(PEPROCESS Process);
typedef PPHYSICAL_MEMORY_RANGE(*MmGetPhysicalMemoryRanges_t)(VOID);
typedef VOID(*ExFreePool_t)(PVOID P);
typedef VOID(*ExFreePoolWithTag_t)(PVOID P, ULONG Tag);
typedef PVOID(*MmMapIoSpace_t)(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType);
typedef PVOID(*MmMapIoSpaceEx_t)(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);
typedef PHYSICAL_ADDRESS(*MmGetPhysicalAddress_t)(PVOID BaseAddress);
typedef PVOID(*MmGetVirtualForPhysical_t)(PHYSICAL_ADDRESS PhysicalAddress);
typedef VOID(*MmUnmapIoSpace_t)(PVOID BaseAddress, SIZE_T NumberOfBytes);
typedef KIRQL(*KfRaiseIrql_t)(KIRQL NewIrql);
typedef VOID(*KeLowerIrql_t)(KIRQL NewIrql);
typedef NTSTATUS(*IoGetDeviceObjectPointer_t)(PUNICODE_STRING ObjectName, ACCESS_MASK DesiredAccess, PFILE_OBJECT* FileObject, PDEVICE_OBJECT* DeviceObject);
typedef PVOID(*MmAllocateContiguousMemory_t)(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS HighestAcceptableAddress);
typedef VOID(*MmFreeContiguousMemory_t)(PVOID BaseAddress);
typedef ULONG(FASTCALL* KeGetCurrentProcessorIndex_t)(VOID);
typedef KIRQL(*KeGetCurrentIrql_t)(VOID);
typedef PIO_STACK_LOCATION(__fastcall* IoGetCurrentIrpStackLocation_t)(PIRP Irp);
typedef VOID(*RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef PVOID(*_InterlockedExchangePointer_t)(volatile PVOID* Target, PVOID Value);
typedef
NTSTATUS
(*PMM_PROTECT_MDL_SYSTEM_ADDRESS) (
    _In_ PMDL MemoryDescriptorList,
    _In_ ULONG NewProtect
    );
typedef
PVOID
(*PMM_MAP_LOCKED_PAGES_SPECIFY_CACHE) (
    _In_ PMDL MemoryDescriptorList,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ MEMORY_CACHING_TYPE CacheType,
    _In_opt_ PVOID RequestedAddress,
    _In_ ULONG BugCheckOnFailure,
    _In_ ULONG Priority
    );


typedef
VOID
(*PMM_UNMAP_LOCKED_PAGES) (
    _In_ PVOID BaseAddress,
    _In_ PMDL MemoryDescriptorList

    );

typedef KPROCESSOR_MODE(*PEX_GET_PREVIOUS_MODE)(void);

enum pe_magic_t {
    dos_header = 0x5a4d,
    nt_headers = 0x4550,
    opt_header = 0x020b
};

struct {
    PEX_GET_PREVIOUS_MODE ExGetPreviousMode;
    PMM_UNMAP_LOCKED_PAGES MmUnmapLockedPages;
    PMM_MAP_LOCKED_PAGES_SPECIFY_CACHE MmMapLockedPagesSpecifyCache;
    PMM_PROTECT_MDL_SYSTEM_ADDRESS MmProtectMdlSystemAddress;
    _InterlockedExchangePointer_t _InterlockedExchangePointer;
    RtlInitUnicodeString_t RtlInitUnicodeString;
    IoGetCurrentIrpStackLocation_t IoGetCurrentIrpStackLocation;
    KeGetCurrentProcessorIndex_t KeGetCurrentProcessorIndex;
    KeGetCurrentIrql_t KeGetCurrentIrql;
    MmCopyMemory_t MmCopyMemory;
    IofCompleteRequest_t IofCompleteRequest;
    PsLookupProcessByProcessId_t PsLookupProcessByProcessId;
    KeStackAttachProcess_t KeStackAttachProcess;
    KeUnstackDetachProcess_t KeUnstackDetachProcess;
    ObfDereferenceObject_t ObfDereferenceObject;
    IoAllocateMdl_t IoAllocateMdl;
    MmProbeAndLockPages_t MmProbeAndLockPages;
    MmGetMdlPfnArray_t MmGetMdlPfnArray;
    MmUnlockPages_t MmUnlockPages;
    IoFreeMdl_t IoFreeMdl;
    RtlEqualUnicodeString_t RtlEqualUnicodeString;
    PsGetProcessSectionBaseAddress_t PsGetProcessSectionBaseAddress;
    MmGetPhysicalMemoryRanges_t MmGetPhysicalMemoryRanges;
    ExFreePool_t ExFreePool;
    ExFreePoolWithTag_t ExFreePoolWithTag;
    MmMapIoSpace_t MmMapIoSpace;
    MmMapIoSpaceEx_t MmMapIoSpaceEx;
    MmGetPhysicalAddress_t MmGetPhysicalAddress;
    MmGetVirtualForPhysical_t MmGetVirtualForPhysical;
    MmUnmapIoSpace_t MmUnmapIoSpace;
    KfRaiseIrql_t KfRaiseIrql;
    KeLowerIrql_t KeLowerIrql;
    IoGetDeviceObjectPointer_t IoGetDeviceObjectPointer;
    MmAllocateContiguousMemory_t MmAllocateContiguousMemory;
    MmFreeContiguousMemory_t MmFreeContiguousMemory;
} func_ptrs;


struct dos_header_t {
    std::int16_t m_magic;
    std::int16_t m_cblp;
    std::int16_t m_cp;
    std::int16_t m_crlc;
    std::int16_t m_cparhdr;
    std::int16_t m_minalloc;
    std::int16_t m_maxalloc;
    std::int16_t m_ss;
    std::int16_t m_sp;
    std::int16_t m_csum;
    std::int16_t m_ip;
    std::int16_t m_cs;
    std::int16_t m_lfarlc;
    std::int16_t m_ovno;
    std::int16_t m_res0[0x4];
    std::int16_t m_oemid;
    std::int16_t m_oeminfo;
    std::int16_t m_res1[0xa];
    std::int32_t m_lfanew;

    [[ nodiscard ]]
    constexpr bool is_valid() {
        return m_magic == pe_magic_t::dos_header;
    }
};

struct data_directory_t {
    std::int32_t m_virtual_address;
    std::int32_t m_size;

    template< class type_t >
    [[ nodiscard ]]
    type_t as_rva(
        std::uintptr_t rva
    ) {
        return reinterpret_cast<type_t>(rva + m_virtual_address);
    }
};
struct import_descriptor_t {
    union {
        std::uint32_t m_characteristics;
        std::uint32_t m_original_first_thunk;
    };
    std::uint32_t m_time_date_stamp;
    std::uint32_t m_forwarder_chain;
    std::uint32_t m_name;
    std::uint32_t m_first_thunk;
};

struct nt_headers_t {
    std::int32_t m_signature;
    std::int16_t m_machine;
    std::int16_t m_number_of_sections;
    std::int32_t m_time_date_stamp;
    std::int32_t m_pointer_to_symbol_table;
    std::int32_t m_number_of_symbols;
    std::int16_t m_size_of_optional_header;
    std::int16_t m_characteristics;

    std::int16_t m_magic;
    std::int8_t m_major_linker_version;
    std::int8_t m_minor_linker_version;
    std::int32_t m_size_of_code;
    std::int32_t m_size_of_initialized_data;
    std::int32_t m_size_of_uninitialized_data;
    std::int32_t m_address_of_entry_point;
    std::int32_t m_base_of_code;
    std::uint64_t m_image_base;
    std::int32_t m_section_alignment;
    std::int32_t m_file_alignment;
    std::int16_t m_major_operating_system_version;
    std::int16_t m_minor_operating_system_version;
    std::int16_t m_major_image_version;
    std::int16_t m_minor_image_version;
    std::int16_t m_major_subsystem_version;
    std::int16_t m_minor_subsystem_version;
    std::int32_t m_win32_version_value;
    std::int32_t m_size_of_image;
    std::int32_t m_size_of_headers;
    std::int32_t m_check_sum;
    std::int16_t m_subsystem;
    std::int16_t m_dll_characteristics;
    std::uint64_t m_size_of_stack_reserve;
    std::uint64_t m_size_of_stack_commit;
    std::uint64_t m_size_of_heap_reserve;
    std::uint64_t m_size_of_heap_commit;
    std::int32_t m_loader_flags;
    std::int32_t m_number_of_rva_and_sizes;

    data_directory_t m_export_table;
    data_directory_t m_import_table;
    data_directory_t m_resource_table;
    data_directory_t m_exception_table;
    data_directory_t m_certificate_table;
    data_directory_t m_base_relocation_table;
    data_directory_t m_debug;
    data_directory_t m_architecture;
    data_directory_t m_global_ptr;
    data_directory_t m_tls_table;
    data_directory_t m_load_config_table;
    data_directory_t m_bound_import;
    data_directory_t m_iat;
    data_directory_t m_delay_import_descriptor;
    data_directory_t m_clr_runtime_header;
    data_directory_t m_reserved;

    [[ nodiscard ]]
    constexpr bool is_valid() {
        return m_signature == pe_magic_t::nt_headers
            && m_magic == pe_magic_t::opt_header;
    }
};

struct export_directory_t {
    std::int32_t m_characteristics;
    std::int32_t m_time_date_stamp;
    std::int16_t m_major_version;
    std::int16_t m_minor_version;
    std::int32_t m_name;
    std::int32_t m_base;
    std::int32_t m_number_of_functions;
    std::int32_t m_number_of_names;
    std::int32_t m_address_of_functions;
    std::int32_t m_address_of_names;
    std::int32_t m_address_of_names_ordinals;
};


struct section_header_t {
    char m_name[0x8];
    union {
        std::int32_t m_physical_address;
        std::int32_t m_virtual_size;
    };
    std::int32_t m_virtual_address;
    std::int32_t m_size_of_raw_data;
    std::int32_t m_pointer_to_raw_data;
    std::int32_t m_pointer_to_relocations;
    std::int32_t m_pointer_to_line_numbers;
    std::int16_t m_number_of_relocations;
    std::int16_t m_number_of_line_numbers;
    std::int32_t m_characteristics;
};

typedef struct _memory_basic_information {
    void* m_base_address;          // Base address of the region
    void* m_allocation_base;       // Base address of allocated range
    std::uint32_t   m_allocation_protect;    // Initial access protection
    std::uint32_t   m_partition_id;         // Data partition ID
    std::uint64_t   m_region_size;          // Size of the region in bytes
    std::uint32_t   m_state;                // Committed, reserved, or free
    std::uint32_t   m_protect;              // Current access protection
    std::uint32_t   m_type;                 // Type of pages
} memory_basic_information, * pmemory_basic_information;

struct list_entry_t {
    list_entry_t* m_flink;
    list_entry_t* m_blink;
};

struct single_list_entry_t {
    single_list_entry_t* m_next;
};

enum pe_characteristics_t : std::uint16_t {
    pe_relocs_stripped = 0x0001,
    pe_executable = 0x0002,
    pe_line_nums_stripped = 0x0004,
    pe_local_syms_stripped = 0x0008,
    pe_aggressive_ws_trim = 0x0010,
    pe_large_address_aware = 0x0020,
    pe_bytes_reversed_lo = 0x0080,
    pe_32bit_machine = 0x0100,
    pe_debug_stripped = 0x0200,
    pe_removable_run_from_swap = 0x0400,
    pe_net_run_from_swap = 0x0800,
    pe_system = 0x1000,
    pe_dll = 0x2000,
    pe_up_system_only = 0x4000,
    pe_bytes_reversed_hi = 0x8000
};

enum view_share_t : std::uint32_t {
    view_share = 1,
    view_unmap = 2
};

enum allocation_type_t : std::uint32_t {
    mem_commit = 0x1000,
    mem_reserve = 0x2000,
    mem_reset = 0x80000,
    mem_large_pages = 0x20000000,
    mem_physical = 0x400000,
    mem_top_down = 0x100000,
    mem_write_watch = 0x200000
};

struct kspin_lock_t {
    volatile long m_lock; // +0x000
};
