//! Hand-written raw UEFI bindings for the M1 loader.
//!
//! Only the protocols and functions the loader actually uses are bound. Field
//! order matches the UEFI specification exactly; every struct is `repr(C)`.
//! On the `x86_64-unknown-uefi` target `extern "efiapi"` is the UEFI calling
//! convention (equivalent to `extern "C"` on this target).

#![allow(non_snake_case)]
#![allow(dead_code)]

use core::ffi::c_void;

pub type Status = usize;
pub type Handle = *mut c_void;
pub type Event = *mut c_void;
pub type PhysicalAddress = u64;

pub const SUCCESS: Status = 0;

/// Error bit (EFI_ERROR_MASK): any status with the high bit set is an error.
pub fn is_error(st: Status) -> bool {
    st & (1usize << (usize::BITS - 1)) != 0
}

/// EFI_ERROR(5) — a buffer passed to GetMemoryMap was too small.
pub const ERR_BUFFER_TOO_SMALL: Status = 0x8000_0000_0000_0005;

pub const fn efierr(n: usize) -> Status {
    (1usize << (usize::BITS - 1)) | n
}

// Memory types (subset).
pub const MEMORY_LOADER_CODE: u32 = 2;
pub const MEMORY_LOADER_DATA: u32 = 3;
pub const MEMORY_CONVENTIONAL: u32 = 7;

// AllocatePages type.
pub const ALLOCATE_ANY_PAGES: u32 = 0;

// File open modes.
pub const FILE_MODE_READ: u64 = 0x1;

/// SetPosition with 0xFFFFFFFFFFFFFFFF seeks to the end of the file.
pub const FILE_POSITION_END: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub d1: u32,
    pub d2: u16,
    pub d3: u16,
    pub d4: [u8; 8],
}

pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = Guid {
    d1: 0x964e_5b22,
    d2: 0x6459,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid {
    d1: 0x5b1b_31a1,
    d2: 0x9562,
    d3: 0x11d2,
    d4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

/// EFI_ACPI_20_TABLE_GUID — VendorTable points at the ACPI RSDP.
pub const EFI_ACPI_20_TABLE_GUID: Guid = Guid {
    d1: 0x8868_e871,
    d2: 0xe4f1,
    d3: 0x11d3,
    d4: [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
};

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u16,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

#[repr(C)]
pub struct SimpleTextOutput {
    pub reset: extern "efiapi" fn(this: *mut SimpleTextOutput, extended_verification: u8) -> Status,
    pub output_string:
        extern "efiapi" fn(this: *mut SimpleTextOutput, string: *const u16) -> Status,
    pub test_string: extern "efiapi" fn(this: *mut SimpleTextOutput, string: *const u16) -> Status,
    pub query_mode: extern "efiapi" fn(
        this: *mut SimpleTextOutput,
        mode_number: usize,
        columns: *mut usize,
        rows: *mut usize,
    ) -> Status,
    pub set_mode: extern "efiapi" fn(this: *mut SimpleTextOutput, mode_number: usize) -> Status,
    pub set_attribute: extern "efiapi" fn(this: *mut SimpleTextOutput, attribute: usize) -> Status,
    pub clear_screen: extern "efiapi" fn(this: *mut SimpleTextOutput) -> Status,
    pub set_cursor_position:
        extern "efiapi" fn(this: *mut SimpleTextOutput, column: usize, row: usize) -> Status,
    pub enable_cursor: extern "efiapi" fn(this: *mut SimpleTextOutput, visible: u8) -> Status,
    pub mode: *mut c_void,
}

#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    pub raise_tpl: extern "efiapi" fn(new_tpl: usize) -> usize,
    pub restore_tpl: extern "efiapi" fn(old_tpl: usize),
    pub allocate_pages: extern "efiapi" fn(
        alloc_type: u32,
        memory_type: u32,
        pages: usize,
        memory: *mut PhysicalAddress,
    ) -> Status,
    pub free_pages: extern "efiapi" fn(memory: PhysicalAddress, pages: usize) -> Status,
    pub get_memory_map: extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut u8,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> Status,
    pub allocate_pool:
        extern "efiapi" fn(pool_type: u32, size: usize, buffer: *mut *mut c_void) -> Status,
    pub free_pool: extern "efiapi" fn(buffer: *mut c_void) -> Status,
    pub create_event: extern "efiapi" fn(
        ty: u32,
        notify_tpl: usize,
        notify_function: *mut c_void,
        notify_context: *mut c_void,
        event: *mut Event,
    ) -> Status,
    pub set_timer: extern "efiapi" fn(event: Event, ty: u32, trigger_time: u64) -> Status,
    pub wait_for_event: extern "efiapi" fn(
        number_of_events: usize,
        event: *const Event,
        index: *mut usize,
    ) -> Status,
    pub signal_event: extern "efiapi" fn(event: Event) -> Status,
    pub close_event: extern "efiapi" fn(event: Event) -> Status,
    pub check_event: extern "efiapi" fn(event: Event) -> Status,
    pub install_protocol_interface: extern "efiapi" fn(
        handle: *mut Handle,
        protocol: *const Guid,
        interface_type: u32,
        interface: *mut c_void,
    ) -> Status,
    pub reinstall_protocol_interface: extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        old_interface: *mut c_void,
        new_interface: *mut c_void,
    ) -> Status,
    pub uninstall_protocol_interface:
        extern "efiapi" fn(handle: Handle, protocol: *const Guid, interface: *mut c_void) -> Status,
    pub handle_protocol: extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
    ) -> Status,
    /// `VOID *Reserved` — mandatory padding slot in the UEFI 2.x layout.
    pub reserved: *mut c_void,
    pub register_protocol_notify: extern "efiapi" fn(
        protocol: *const Guid,
        event: Event,
        registration: *mut *mut c_void,
    ) -> Status,
    pub locate_handle: extern "efiapi" fn(
        search_type: u32,
        protocol: *const Guid,
        search_key: *const c_void,
        buffer_size: *mut usize,
        buffer: *mut Handle,
    ) -> Status,
    pub locate_device_path: extern "efiapi" fn(
        protocol: *const Guid,
        device_path: *mut *mut c_void,
        device: *mut Handle,
    ) -> Status,
    pub install_configuration_table:
        extern "efiapi" fn(guid: *const Guid, table: *mut c_void) -> Status,
    pub load_image: extern "efiapi" fn(
        boot_policy: u8,
        parent_image_handle: Handle,
        device_path: *mut c_void,
        source_buffer: *mut c_void,
        source_size: usize,
        image_handle: *mut Handle,
    ) -> Status,
    pub start_image: extern "efiapi" fn(
        image_handle: Handle,
        exit_data_size: *mut usize,
        exit_data: *mut *mut u16,
    ) -> Status,
    pub exit: extern "efiapi" fn(
        image_handle: Handle,
        exit_status: Status,
        exit_data_size: usize,
        exit_data: *mut u16,
    ) -> Status,
    pub unload_image: extern "efiapi" fn(image_handle: Handle) -> Status,
    pub exit_boot_services: extern "efiapi" fn(image_handle: Handle, map_key: usize) -> Status,
    pub get_next_monotonic_count: extern "efiapi" fn(count: *mut u64) -> Status,
    pub stall: extern "efiapi" fn(microseconds: usize) -> Status,
    pub set_watchdog_timer: extern "efiapi" fn(
        timeout: u64,
        watchdog_code: u64,
        data_size: usize,
        watchdog_data: *mut u16,
    ) -> Status,
    pub connect_controller: extern "efiapi" fn(
        controller_handle: Handle,
        driver_image_handle: *mut Handle,
        remaining_device_path: *mut c_void,
        recursive: u8,
    ) -> Status,
    pub disconnect_controller: extern "efiapi" fn(
        controller_handle: Handle,
        driver_image_handle: *mut Handle,
        child_handle: *mut Handle,
    ) -> Status,
    pub open_protocol: extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
        agent_handle: Handle,
        controller_handle: Handle,
        attributes: u32,
    ) -> Status,
    pub close_protocol: extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        agent_handle: Handle,
        controller_handle: Handle,
    ) -> Status,
    pub open_protocol_information: extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        entry_buffer: *mut *mut c_void,
        entry_count: *mut usize,
    ) -> Status,
    pub protocols_per_handle: extern "efiapi" fn(
        handle: Handle,
        protocol_buffer: *mut *mut *mut Guid,
        protocol_buffer_count: *mut usize,
    ) -> Status,
    pub locate_handle_buffer: extern "efiapi" fn(
        search_type: u32,
        protocol: *const Guid,
        search_key: *const c_void,
        num_handles: *mut usize,
        buffer: *mut *mut Handle,
    ) -> Status,
    pub locate_protocol: extern "efiapi" fn(
        protocol: *const Guid,
        registration: *const c_void,
        interface: *mut *mut c_void,
    ) -> Status,
    pub install_multiple_protocol_interfaces:
        extern "efiapi" fn(handle: *mut Handle, ...) -> Status,
    pub uninstall_multiple_protocol_interfaces: extern "efiapi" fn(handle: Handle, ...) -> Status,
    pub calculate_crc32:
        extern "efiapi" fn(data: *const c_void, data_size: usize, crc32: *mut u32) -> Status,
    pub copy_mem:
        extern "efiapi" fn(destination: *mut c_void, source: *const c_void, length: usize),
    pub set_mem: extern "efiapi" fn(buffer: *mut c_void, size: usize, value: u8),
    pub create_event_ex: extern "efiapi" fn(
        ty: u32,
        notify_tpl: usize,
        notify_function: *mut c_void,
        notify_context: *const c_void,
        event_group: *const Guid,
        event: *mut Event,
    ) -> Status,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub standard_error_handle: Handle,
    pub std_err: *mut SimpleTextOutput,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut ConfigurationTable,
}

#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: extern "efiapi" fn(image_handle: Handle) -> Status,
}

#[repr(C)]
pub struct SimpleFileSystem {
    pub revision: u64,
    pub open_volume:
        extern "efiapi" fn(this: *mut SimpleFileSystem, root: *mut *mut File) -> Status,
}

#[repr(C)]
pub struct File {
    pub revision: u64,
    pub open: extern "efiapi" fn(
        this: *mut File,
        new_handle: *mut *mut File,
        filename: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> Status,
    pub close: extern "efiapi" fn(this: *mut File) -> Status,
    pub delete: extern "efiapi" fn(this: *mut File) -> Status,
    pub read:
        extern "efiapi" fn(this: *mut File, buffer_size: *mut usize, buffer: *mut u8) -> Status,
    pub write:
        extern "efiapi" fn(this: *mut File, buffer_size: *mut usize, buffer: *mut u8) -> Status,
    pub get_position: extern "efiapi" fn(this: *mut File, position: *mut u64) -> Status,
    pub set_position: extern "efiapi" fn(this: *mut File, position: u64) -> Status,
    pub get_info: extern "efiapi" fn(
        this: *mut File,
        information_type: *const Guid,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> Status,
    pub set_info: extern "efiapi" fn(
        this: *mut File,
        information_type: *const Guid,
        buffer_size: usize,
        buffer: *const u8,
    ) -> Status,
    pub flush: extern "efiapi" fn(this: *mut File) -> Status,
}

/// UEFI memory descriptor (48 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryDescriptor {
    pub ty: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}
