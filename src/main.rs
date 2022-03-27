use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::str::FromStr;
use winapi::ctypes::c_void;
use winapi::shared::{
    minwindef::{DWORD, FALSE, HMODULE},
    ntdef::{CHAR, NULL},
};
use winapi::um::{
    errhandlingapi::GetLastError,
    handleapi::CloseHandle,
    memoryapi::{ReadProcessMemory, WriteProcessMemory},
    processthreadsapi::OpenProcess,
    psapi::EnumProcessModules,
    psapi::GetModuleFileNameExA,
    psapi::GetModuleInformation,
    psapi::GetProcessImageFileNameA,
    psapi::MODULEINFO,
    winnt::PROCESS_ALL_ACCESS,
    winuser::{FindWindowA, GetWindowThreadProcessId},
};
// External Simple Hack for Assault Cube ver 1202

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
            println!("Base Address: {:#08x}\n", base_address as usize,);
            /*
            Local Entity Object Offset: + 10F4F4   (static)
                Health                : + F8   (4 bytes)
                Default Weapon Ammo   : + 150  (4 bytes)
            */
            let mut health = 0u32;
            let mut ammo = 0u32;

            let mut address_entity_object_addr: usize = 0;
            ReadProcessMemory(
                process_handle,
                (base_address as usize + 0x10F4F4) as *mut c_void,
                &mut address_entity_object_addr as *mut _ as *mut c_void,
                mem::size_of::<usize>(),
                core::ptr::null_mut(),
            );
            let health_pointer = (address_entity_object_addr + 0xF8) as *mut c_void;
            let ammo_pointer = (address_entity_object_addr + 0x150) as *mut c_void;
            ReadProcessMemory(
                process_handle,
                health_pointer,
                &mut health as *mut _ as *mut c_void,
                mem::size_of::<u32>(),
                core::ptr::null_mut(),
            );
            ReadProcessMemory(
                process_handle,
                ammo_pointer,
                &mut ammo as *mut _ as *mut c_void,
                mem::size_of::<u32>(),
                core::ptr::null_mut(),
            );
            println!("Current Health: {}", health);
            println!("Current Ammo  : {}", ammo);

            println!("Input your desired health: ");
            let desired_health = get_number_input::<u32>();
            println!("Input your desired ammo: ");
            let desired_ammo = get_number_input::<u32>();

            WriteProcessMemory(
                process_handle,
                health_pointer,
                &desired_health as *const _ as *const c_void,
                mem::size_of::<u32>(),
                core::ptr::null_mut(),
            );
            WriteProcessMemory(
                process_handle,
                ammo_pointer,
                &desired_ammo as *const _ as *const c_void,
                mem::size_of::<u32>(),
                core::ptr::null_mut(),
            );

            println!("Set desired changes!");
        } else {
            println!("Failed to find the module");
        }

        if CloseHandle(process_handle) == 0 {
            panic!("Failed to close handle?!");
        }
    }
}
fn get_number_input<T: FromStr>() -> T {
    let mut string = String::new();
    loop {
        io::stdin().read_line(&mut string).unwrap();
        match string.trim().parse() {
            Ok(number) => return number,
            Err(_) => (),
        }
        string.clear();
    }
}
