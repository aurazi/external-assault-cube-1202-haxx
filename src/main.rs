use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::CHAR;
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::EnumProcessModules;
use winapi::um::psapi::GetModuleFileNameExA;
use winapi::um::psapi::GetModuleInformation;
use winapi::um::psapi::GetProcessImageFileNameA;
use winapi::um::psapi::MODULEINFO;
use winapi::um::winnt::PROCESS_ALL_ACCESS;
use winapi::um::winuser::FindWindowA;
use winapi::um::winuser::GetWindowThreadProcessId;

fn main() {
    unsafe {
        let window_name = CString::new("AssaultCube").expect("Failed to create CString");
        let window_handle = FindWindowA(NULL as *const i8, window_name.as_ptr());
        if window_handle.is_null() {
            println!("Failed to find window!");
            return;
        }
        let mut pid = mem::zeroed::<DWORD>();
        GetWindowThreadProcessId(window_handle, &mut pid);
        println!("ProcessID found: {pid}");

        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if process_handle.is_null() {
            panic!(
                "Failed to get process handle\nLast thread error code: {}",
                GetLastError()
            );
        }

        let mut executable_name = [-1; 255];
        if GetProcessImageFileNameA(process_handle, executable_name.as_mut_ptr(), 255) == 0 {
            panic!(
                "Failed to get executable name\nLast thread error code: {}",
                GetLastError()
            );
        }
        let cexecutable_name = CStr::from_ptr(executable_name.as_ptr());
        let strexecutable_name = cexecutable_name.to_str().unwrap();
        println!("Executable Path: {}", strexecutable_name);

        let mut modules = [mem::zeroed::<HMODULE>(); 1024];
        let mut cb = mem::zeroed::<DWORD>();
        let mut hmodule_found: HMODULE = core::ptr::null_mut();

        println!("{}", mem::size_of::<HMODULE>());

        if EnumProcessModules(
            process_handle,
            modules.as_mut_ptr(),
            mem::size_of_val(&modules) as u32,
            &mut cb,
        ) != 0
        {
            for hmodule in modules.into_iter() {
                if hmodule.is_null() {
                    break;
                }
                let mut hmodulefn = [-1; 255];
                if GetModuleFileNameExA(
                    process_handle,
                    hmodule,
                    hmodulefn.as_mut_ptr(),
                    (mem::size_of_val(&hmodulefn) / mem::size_of::<CHAR>())
                        .try_into()
                        .unwrap(),
                ) != 0
                {
                    let needle = CStr::from_ptr(hmodulefn.as_ptr().add(2)).to_str().unwrap();
                    if strexecutable_name.ends_with(needle) {
                        hmodule_found = hmodule;
                    }
                }
            }
        }

        if !hmodule_found.is_null() {
            let mut module_info = mem::zeroed::<MODULEINFO>();
            if GetModuleInformation(
                process_handle,
                hmodule_found,
                &mut module_info,
                mem::size_of::<MODULEINFO>() as u32,
            ) == 0
            {
                panic!(
                    "Failed to get module information\nLast thread error code: {}",
                    GetLastError()
                );
            }
            let base_address = module_info.lpBaseOfDll;
            let entry_point_address = module_info.EntryPoint;
            println!(
                "Base Address: {}\nEntry Point Address: {}",
                base_address as usize, entry_point_address as usize
            );
        } else {
            println!("Failed to find the module");
        }

        if CloseHandle(process_handle) == 0 {
            panic!("Failed to close handle?!");
        }
    }
}
