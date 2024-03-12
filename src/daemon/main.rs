use rusqlite::Connection;
use miniwall::*;
use windows::{core::GUID, Win32::Foundation::HANDLE};
#[link(name="converter", kind="static")]
#[warn(dead_code)]
extern "C" {
    fn guid_to_string(guid: *const GUID) -> *const u16;
}
unsafe fn wchar_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.offset(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len as usize);
    String::from_utf16_lossy(slice)
}
fn main(){
    let mut connection: Connection = db_connect();
    let filters: Vec<Filter> = Filter::get_all(&mut connection);
    let mut engine_handle: HANDLE = Default::default();
    let engine_initialization_result = unsafe { 
        initialize_filtering_engine(&mut engine_handle) 
    };
    if engine_initialization_result != 0 {
        panic!("engine cannot be initialized!");
    }
    for mut filter in filters {
        if filter.name.contains("-on-v4-connect-layer"){
            let guid: GUID = unsafe { block_app_once_on_startup("v4", &filter.name, &filter.file_path, engine_handle) };
            filter.guid = unsafe { 
                wchar_to_string(
                    guid_to_string(
                        &guid)) 
                };
            filter.update(&mut connection);
        }else if filter.name.contains("-on-v6-connect-layer"){
            let guid: GUID = unsafe { block_app_once_on_startup("v4", &filter.name, &filter.file_path, engine_handle) };

            filter.guid = unsafe { 
                wchar_to_string(
                guid_to_string(&guid)) 
                };
            filter.update(&mut connection);
        }
    }
    unsafe {
        close_filtering_engine(engine_handle);
    }
}