
use libc::c_void;
use rusqlite::Connection;
use windows::core::{Result, GUID};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{FwpmFreeMemory0, FWPM_FILTER0};
use std::env;
use prettytable::{row, Table};
use crate::utils::{*, database_n_model::*,filtering_abstractions::*};
pub mod utils;

fn main() -> Result<()> {
    // Open a session to the WFP engine
    let mut engine_handle: HANDLE = Default::default();
    unsafe {
        initialize_filtering_engine(&mut engine_handle)
    };
    let mut connection = db_connect();
    let args: Vec<String> = env::args().skip(1).collect();
    selector_of_arguments(&args, engine_handle,&mut connection);

    Ok(())
}
fn selector_of_arguments(arguments: &Vec<String>, engine_handle: HANDLE, connection: &mut Connection){
    match arguments.get(0).map(|s| s.as_str()) {
        Some("block-app-filter") => block_app_selected_in_cli(arguments, engine_handle, connection),
        Some("delete-filter") => delete_filter_selected(arguments,connection, engine_handle),
        Some("list-all") => list_all_selected(connection),
        _ => todo!()
    }
}
fn list_all_selected(connection: &mut Connection){
    let filters = Filter::get_all(connection);
    let mut table = Table::new();
    table.add_row(row!["ID","GUID","NAME","FILEPATH","ACTION"]);
    for filter in filters{
        table.add_row(row![filter.id, filter.guid, filter.name, filter.file_path, filter.action]);
    }
    table.printstd();
}
fn delete_filter_selected(arguments: &Vec<String>,connection: &mut Connection, engine_handle: HANDLE){
    let filters = Filter::get_by_file_path(connection, arguments[1].to_string());
    for filter in filters{
        filter.delete(connection);
        let filter_guid = filter.guid.as_str();
        unsafe { 
            _delete_filter(engine_handle, &mut GUID::from(&filter_guid[1..filter_guid.len() -1]));
        }
    }
}
fn block_app_selected_in_cli(arguments: &Vec<String>, engine_handle: HANDLE, connection:&mut Connection){
    if arguments[1] == "path".to_string(){
        if file_exist(&arguments[2]){
            if arguments[3] == "name".to_string(){
                unsafe { 
                    delete_all_with_file_path(connection,&arguments[2],engine_handle);
                    let filters_v4_and_v6 = _block_app(engine_handle, arguments[4].as_str(),arguments[2].as_str());
                    
                    let mut filter = filters_v4_and_v6.filter1;
                    let filter_model1_name = Layer::V6.to_filter_name(arguments[4].clone().as_str());
                    let filepath = &arguments[2];
                    let filter_model1_guid = &mut filter.filterKey; 
                    let filter_model1 = Filter::new(
                        filter_model1_name,
                        _action_to_string(&filter.action).to_owned(),
                        filepath.to_string(),
                        0,
                        filter_model1_guid);

                    let mut filter2 = filters_v4_and_v6.filter2;
                    let filter_model2_name = Layer::V4.to_filter_name(arguments[4].clone().as_str());
                    let filter_model2_guid = &mut filter2.filterKey;

                    let filter_model2 = Filter::new(
                        filter_model2_name,
                        _action_to_string(&filter.action).to_owned(),
                        filepath.to_string(),
                        0,
                        filter_model2_guid);

                    filter_model1.save(connection);
                    filter_model2.save(connection);
                }
            }else{
                panic!("command structure is the following: **miniwall block-app-filter path <path> name <name>**");
            }
        }else{
            panic!("file path does not exists!");
        }
    }else {
        panic!("command structure is the following: **miniwall block-app-filter path <path> name <name>**");
    }
}

fn activate_whitelist_mode_selected(arguments: &Vec<String>,engine_handle: HANDLE, connection: &mut Connection){
    
}
fn deactivate_whitelist_mode_selected(){}
fn allow_app_selected(){}
fn file_exist(file_path: &str) -> bool{
    match std::fs::metadata(file_path).is_ok() {
        true => true,
        false => false
    }
}
// THIS IS TESTING CODE
#[allow(dead_code)]
fn enumerate_and_print_filters(engine_handle: HANDLE) {
        let mut enum_handle: HANDLE = Default::default();
        let mut count: u32 = Default::default();
        let mut filters: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
    
        // FILTERS ENUMERATION
        unsafe {
            create_enum_handle(engine_handle, &mut enum_handle);
            filter_enum(engine_handle, enum_handle, &mut count, &mut filters);
            println!("count: {}", count);
            for i in 0..count {
                if i == 0 {
                    println!("long : {}", count);
                }
    
                let filter = *filters.offset(i as isize);
                let filter_key_ptr = std::ptr::addr_of!((*filter).filterKey);
    
                if wchar_to_string((*filter).displayData.name.0).contains("filter to block chrome") {
                    println!("position: {}", i);
                    println!("Filter key: {}", wchar_to_string(guid_to_string(filter_key_ptr)));
                    println!("Filter name: {}", wchar_to_string((*filter).displayData.name.0));
                }
                // println!("Filter name: {}", wchar_to_string((*filter).displayData.name.0));
                std::ptr::drop_in_place(filter);
            }
            println!("END");
            if filters.is_null() {
                println!("freed");
            } else {
                let filters_ptr_ptr: *mut *mut c_void = &mut filters as *mut _ as *mut *mut c_void;
                FwpmFreeMemory0(filters_ptr_ptr);
            }
            destroy_enum_handle(engine_handle, enum_handle);
        }
    }