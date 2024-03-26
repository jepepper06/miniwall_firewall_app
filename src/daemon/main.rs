use rusqlite::Connection;
use windows::{core::GUID, Win32::Foundation::HANDLE};
use crate::{database_n_model::*, utils::*,filtering_abstractions::*};
#[path ="../utils/mod.rs"]
mod utils;
fn main(){
    let mut connection: Connection = db_connect();
    let filters: Vec<Filter> = Filter::get_all(&mut connection);
    let mut engine_handle: HANDLE = Default::default();
    unsafe { 
        initialize_filtering_engine(&mut engine_handle) 
    };
    for mut filter in filters {
        if filter.name.contains(Layer::V4.to_str()){
            println!("file_path: {}",&filter.file_path);
            let guid: GUID = unsafe { block_app_once_on_startup(Layer::V4, &filter.name, &filter.file_path, engine_handle) };
            filter.guid = unsafe { 
                wchar_to_string(
                    guid_to_string(
                        &guid)) 
                };
            filter.update(&mut connection);
        }else if filter.name.contains(Layer::V6.to_str()){
            let guid: GUID = unsafe { block_app_once_on_startup(Layer::V6, &filter.name, &filter.file_path, engine_handle) };

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
    println!("hola este es el fin!");
}