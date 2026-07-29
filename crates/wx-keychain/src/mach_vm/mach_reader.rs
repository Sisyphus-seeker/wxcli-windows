//! Mach VM reader: attaches to a process and reads its memory regions.
//!
//! This module is macOS-only (`#[cfg(target_os = "macos")]`).

use mach2::kern_return::KERN_SUCCESS;
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_deallocate, mach_vm_read, mach_vm_region};
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, VM_REGION_BASIC_INFO_COUNT_64};

use crate::error::KeychainError;
use crate::mach_vm::reader::{MemRegion, MemoryReader};

/// Reads memory from a running process using Mach VM APIs.
pub struct MachVmReader {
    task: u32, // mach_port_t
}

impl MachVmReader {
    /// Attach to a process by PID. Requires appropriate privileges
    /// (root, or the target process must be ad-hoc signed).
    pub fn attach(pid: u32) -> Result<Self, KeychainError> {
        let mut task: u32 = 0;
        let kr = unsafe { task_for_pid(mach_task_self(), pid as i32, &mut task) };
        if kr != KERN_SUCCESS {
            return Err(KeychainError::TaskForPidFailed { pid, kr });
        }
        Ok(Self { task })
    }
}

impl MemoryReader for MachVmReader {
    fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError> {
        let mut regions = Vec::new();
        let mut address: u64 = 0;

        loop {
            let mut size: u64 = 0;
            let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
            let mut info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name: u32 = 0;

            let kr = unsafe {
                mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &mut info_cnt,
                    &mut object_name,
                )
            };

            if kr != KERN_SUCCESS {
                break; // No more regions.
            }

            let protection = info[0];
            if (protection & VM_PROT_READ != 0) && (protection & VM_PROT_WRITE != 0) {
                regions.push(MemRegion {
                    start: address,
                    end: address + size,
                });
            }

            address += size;
        }

        Ok(regions)
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError> {
        let mut data_ptr: usize = 0; // vm_offset_t
        let mut data_cnt: u32 = 0;

        let kr = unsafe {
            mach_vm_read(
                self.task,
                addr,
                len as u64,
                &mut data_ptr as *mut usize,
                &mut data_cnt,
            )
        };

        if kr != KERN_SUCCESS {
            return Err(KeychainError::Other(format!(
                "mach_vm_read failed at 0x{addr:x} len={len}: kr={kr}"
            )));
        }

        let result = unsafe {
            std::slice::from_raw_parts(data_ptr as *const u8, data_cnt as usize).to_vec()
        };

        // Deallocate the kernel-allocated buffer.
        unsafe {
            mach_vm_deallocate(mach_task_self(), data_ptr as u64, data_cnt as u64);
        }

        Ok(result)
    }
}
