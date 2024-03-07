use winapi::um::processthreadsapi::{OpenThread, SuspendThread, ResumeThread, GetThreadId, GetThreadContext, SetThreadContext};
use winapi::um::winnt::{THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME, CONTEXT, CONTEXT_FULL};

fn main() {
    // Define the target address to jump to
    let target_addr: usize = 0x00401000;

    // Create a buffer to store the trampoline code
    let mut trampoline_buf = Vec::new();

    // Write the trampoline code to the buffer
    trampoline_buf.push(0xE9); // JMP opcode
    let jump_offset = target_addr.wrapping_sub(trampoline_buf.len() + 5); // Calculate the relative jump offset
    trampoline_buf.extend_from_slice(&(jump_offset as i32).to_le_bytes()); // Write the jump offset as little-endian bytes

    // Get the current process ID and handle errors
    let mut process_id = 0;
    if let Err(e) = GetCurrentProcessIdW(&mut process_id) {
        println!("Error getting current process ID: {}", e);
        return;
    }

    // Open the target DLL file
    let mut file = File::open("target.dll").unwrap();
    let mut dll_bytes = Vec::new();
    file.read_to_end(&mut dll_bytes).unwrap();

    // Get a handle to the target process (replace this with your process handling logic)
    let process_handle = match OpenProcessW(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, process_id) {
        Ok(p) => p,
        Err(e) => {
            println!("Error opening target process: {}", e);
            return;
        }
    };

    // Allocate memory for the trampoline code within the target process
    let trampoline_addr = unsafe {
        let size = trampoline_buf.len();
        let addr = VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if addr.is_null() {
            panic!("Failed to allocate memory in the target process");
        }
        addr as usize
    };

    // Write the trampoline code to the allocated memory within the target process
    unsafe {
        WriteProcessMemory(
            process_handle,
            trampoline_addr as *mut _,
            trampoline_buf.as_ptr() as *const _,
            trampoline_buf.len(),
            std::ptr::null_mut(),
        );
    }

    // Now trampoline code is injected into the target process at trampoline_addr

    // Obtain the handle to the target thread (replace this with your thread handling logic)
    let thread_handle = unsafe {
        OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, GetThreadId(process_handle))
    };
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

    // Read and modify the thread's context
    let mut context = CONTEXT::default();
    context.ContextFlags = CONTEXT_FULL;
    unsafe {
        GetThreadContext(thread_handle, &mut context);
        // Modify context.Eip (instruction pointer) to point to your injected code
        context.Eip = trampoline_addr as DWORD;
        SetThreadContext(thread_handle, &context);
    }

    // Resume the thread's execution
    let resume_count = unsafe { ResumeThread(thread_handle) };
    if resume_count == DWORD::MAX {
        println!("Failed to resume thread");
        return;
    }
}