use std::process::Command;
use std::collections::HashMap;
use rusqlite::*;
use windows::{core::GUID, 
Win32::
    {
    Foundation::HANDLE, 
    NetworkManagement::WindowsFilteringPlatform::
        {
        FWPM_ACTION0, 
        FWP_ACTION_BLOCK, 
        FWP_ACTION_CALLOUT_INSPECTION, 
        FWP_ACTION_CALLOUT_TERMINATING, 
        FWP_ACTION_CALLOUT_UNKNOWN, 
        FWP_ACTION_CONTINUE, 
        FWP_ACTION_PERMIT}}};
use rusqlite::Connection;

use crate::DAO;

use self::{database_n_model::Filter,filtering_abstractions::*};
pub mod database_n_model;
pub mod filtering_abstractions;
#[link(name="converter", kind="static")]
#[warn(dead_code)]
extern "C" {
    pub fn guid_to_string(guid: *const GUID) -> *const u16;
}
pub unsafe fn wchar_to_string(ptr: *const u16) -> String {
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

// UTILS
pub fn _action_to_string(action: &FWPM_ACTION0) -> &'static str {
        match action.r#type {
        FWP_ACTION_BLOCK => "Block",
        FWP_ACTION_PERMIT => "Permit",
        FWP_ACTION_CALLOUT_TERMINATING => "Callout Terminating",
        FWP_ACTION_CALLOUT_INSPECTION => "Callout Inspection",
        FWP_ACTION_CALLOUT_UNKNOWN => "Callout Unknown",
        FWP_ACTION_CONTINUE => "Continue",
        _ => "",
    }
}

struct NetworkCommandResult {
    _local_address: String,
    _local_port: String,
    _remote_address: String,
    _remote_port: String,
    _state: String,
    _executable_path: String,
}
fn _vector_to_hashmap(results: Vec<NetworkCommandResult>) -> HashMap<String, NetworkCommandResult> {
    let mut map: HashMap<String, NetworkCommandResult> = HashMap::new();

    for result in results {
        let executable_path = result._executable_path.clone();
        map.insert(executable_path, result);
    }

    map
}
impl NetworkCommandResult {
    fn new_from_line(line: &str) -> Option<Self> {
        let mut parts = line.trim().splitn(6, char::is_whitespace);

        if let (Some(local_address), Some(local_port), Some(remote_address), Some(remote_port), Some(state), Some(executable_path)) =
            (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            )
        {
            Some(Self {
                _local_address: local_address.to_string(),
                _local_port: local_port.to_string(),
                _remote_address: remote_address.to_string(),
                _remote_port: remote_port.to_string(),
                _state: state.to_string(),
                _executable_path: executable_path.to_string(),
            })
        } else {
            None
        }
    }
}


#[allow(dead_code)]
fn get_tcp_connections() -> Result<Vec<NetworkCommandResult>, String> {
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            "$tcpConnections = Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess;
            foreach ($connection in $tcpConnections) {
                $processId = $connection.OwningProcess;
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue;
                if ($process -ne $null) {
                    $executablePath = $process.Path;
                    if ($executablePath -ne $null) {
                        $connection.LocalAddress + ' ' + $connection.LocalPort + ' ' + $connection.RemoteAddress + ' ' + $connection.RemotePort + ' ' + $connection.State + ' ' + $executablePath;
                    }
                }
            }",
        ])
        .output()
        .expect("Failed to execute PowerShell command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let connections: Vec<NetworkCommandResult> = stdout
            .lines()
            .filter_map(|line| NetworkCommandResult::new_from_line(line))
            .collect();
        Ok(connections)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
#[allow(dead_code)]
pub fn allow_app(connection: &mut Connection, file_path: &str,engine_handle: HANDLE,filter_name: &str){
    delete_all_with_file_path(connection, file_path, engine_handle);
    let filters_on_v6_n_v4 = create_allow_app_filters(file_path, filter_name, engine_handle);
    let filter_on_v6_layer = filters_on_v6_n_v4.filter1;
    let filter_on_v4_layer = filters_on_v6_n_v4.filter2;

    let filter_model_on_v6_layer = Filter::new(
        Layer::V6.to_filter_name(filter_name),
        _action_to_string(&filter_on_v6_layer.action).to_owned(),
        file_path.to_string(),
        0,
        &filter_on_v6_layer.filterKey);
    
    let filter_model_on_v4_layer = Filter::new(
        Layer::V4.to_filter_name(filter_name),
        _action_to_string(&filter_on_v4_layer.action).to_owned(),
        file_path.to_string(),
        0,
        &filter_on_v4_layer.filterKey);
        
    filter_model_on_v6_layer.save(connection);
    filter_model_on_v4_layer.save(connection);
    
}
#[allow(dead_code)]
pub fn delete_all_with_file_path(connection: &mut Connection, file_path: &str,engine_handle: HANDLE){
    let filters_by_path = Filter::get_by_file_path(connection, file_path.to_string());
    if filters_by_path.len() == 0 {
        ()
    }
    for filter in filters_by_path {
        let guid_len = filter.guid.len();
        let mut guid = GUID::from(&filter.guid.as_str()[0..guid_len - 1]);
        unsafe { _delete_filter(engine_handle, &mut guid) } 
        filter.delete(connection);
    }
}
#[allow(dead_code)]
pub fn activate_whitelist_mode(connection: &mut Connection,engine_handle: HANDLE, filter_name: &str){
    let all_filters = Filter::get_all(connection);
    for filter in all_filters {
        let guid_len = filter.guid.len();
        let mut guid = GUID::from(&filter.guid.as_str()[0..guid_len - 1]);
        unsafe { _delete_filter(
            engine_handle, &mut guid); 
        }
    }
    Filter::delete_all(connection);
    let all_connections  = get_tcp_connections().expect("error while retriving connections!");
    let set_of_connections = _vector_to_hashmap(all_connections);
    for conn in set_of_connections {
        unsafe { 
            _block_app(engine_handle, filter_name, conn.0.as_str()) 
        };
    }
}
#[allow(dead_code)]
pub fn disable_whitelist_mode(connection: &mut Connection,engine_handle: HANDLE){
    let all_filters = Filter::get_all(connection);
    for filter in all_filters {
        let guid_len = filter.guid.len();
        let mut guid = GUID::from(&filter.guid.as_str()[0..guid_len - 1]);
        unsafe {
            _delete_filter(engine_handle, &mut guid);
        }
        Filter::delete_all(connection);
    }
}
// TEST
// #[cfg(test)]
// mod test_utils_mod {
//     use libc::wchar_t;
//     use windows::core::GUID;

//     use super::guid_to_string;

//     const GUID_VALUE: GUID = GUID::from_values(
//         0x12345678,
//         0x9ABC,
//         0xDEF0,
//         [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
//     );

//     #[test]
//     fn test_guid_to_string(){
//         assert_eq!(true, true)
//     }
// }
