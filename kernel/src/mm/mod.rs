//! Memory management (M2): physical memory manager, kernel heap, and the
//! higher-half VM takeover.

pub mod addrspace;
pub mod heap;
pub mod pmm;
pub mod selftest;
pub mod vm;
