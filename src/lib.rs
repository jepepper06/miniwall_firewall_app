use libc::c_void;
use widestring::U16CString;
use rusqlite::*;
use windows::{core::{GUID, PCWSTR}, 
Win32::
    {
    Foundation::HANDLE, 
    NetworkManagement::WindowsFilteringPlatform::
        {
        FwpmEngineClose0, 
        FwpmEngineOpen0, 
        FwpmFilterAdd0, 
        FwpmFilterCreateEnumHandle0, 
        FwpmFilterDeleteByKey0, 
        FwpmFilterDestroyEnumHandle0, 
        FwpmFilterEnum0, 
        FwpmFreeMemory0, 
        FwpmGetAppIdFromFileName0, 
        FWPM_ACTION0, 
        FWPM_CONDITION_ALE_APP_ID, 
        FWPM_FILTER0, FWPM_FILTER_CONDITION0, 
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, 
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, 
        FWP_ACTION_BLOCK, 
        FWP_ACTION_CALLOUT_INSPECTION, 
        FWP_ACTION_CALLOUT_TERMINATING, 
        FWP_ACTION_CALLOUT_UNKNOWN, 
        FWP_ACTION_CONTINUE, 
        FWP_ACTION_PERMIT, 
        FWP_ACTION_TYPE, FWP_BYTE_BLOB, 
        FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL}, 
    System::Rpc::RPC_C_AUTHN_WINNT}};
use rusqlite::Connection;
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
// WFP ABSTRACTIONS OVER WINDOWS CRATE
pub unsafe fn initialize_filtering_engine(borrowed_handle: &mut HANDLE) -> u32 {
    FwpmEngineOpen0(
        None,
        RPC_C_AUTHN_WINNT,
        None,
        None,
        borrowed_handle,
    )
}

pub unsafe fn close_filtering_engine(handle: HANDLE){
    FwpmEngineClose0(handle);
}
// THIS FUNCTION MUST BE EXTENDED IN FURTHER IMPLEMENTATIONS
pub fn _string_action_to_action_type(string_action: &str) -> FWP_ACTION_TYPE {
    match string_action.to_lowercase().as_str() {
        "block" => FWP_ACTION_BLOCK,
        _ => panic!("type does not exists")
    }
}
pub unsafe fn create_enum_handle(engine_handle: HANDLE,enum_handle_pointer: &mut HANDLE){
    FwpmFilterCreateEnumHandle0(engine_handle, None, enum_handle_pointer);
}
pub unsafe fn destroy_enum_handle(engine_handle: HANDLE, enum_handle: HANDLE){
    FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
}
pub unsafe fn filter_enum(engine_handle: HANDLE,enum_handle: HANDLE,count: *mut u32,filters: *mut *mut *mut FWPM_FILTER0){
    FwpmFilterEnum0(engine_handle, enum_handle,8192,filters,count);
}
pub unsafe fn _free_filters_memory(mut filters: *mut *mut *mut FWPM_FILTER0){
    let filters_ptr_ptr: *mut *mut c_void = &mut filters as *mut _ as *mut *mut c_void;
    FwpmFreeMemory0(filters_ptr_ptr);
}
pub unsafe fn _add_filter(engine_handle: HANDLE,filter: FWPM_FILTER0) {
    let result = FwpmFilterAdd0(
        engine_handle,
        std::ptr::addr_of!(filter),
        None, 
        None);
    if result != 0 {
        panic!("the filter could not be added!")
    }
}
pub unsafe fn _delete_filter(engine_handle: HANDLE,guid: &mut GUID){
    let result = FwpmFilterDeleteByKey0(engine_handle, guid);
    if result != 0{
        panic!("error while deleting the filter!");
    }
}
pub struct FilterOnV4AndV6{
    pub filter1: FWPM_FILTER0,
    pub filter2: FWPM_FILTER0
}

pub unsafe fn _block_app(engine_handle: HANDLE,filter_name: &str, filename: &str) -> FilterOnV4AndV6 {
    let mut filter_name = U16CString::from_str(filter_name).unwrap();
    let app_filename_path = U16CString::from_str(filename).unwrap();
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    unsafe {
        let app_filename = PCWSTR(app_filename_path.as_ptr());
        let get_app_id_from_filename = FwpmGetAppIdFromFileName0(app_filename, &mut app_id);
        if get_app_id_from_filename != 0 {
            panic!("the app id is not retrieved successfully!");
        }
    }
    let mut condition = FWPM_FILTER_CONDITION0::default();
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.Anonymous.byteBlob = app_id;

    let mut filter = FWPM_FILTER0::default();
    filter.filterKey = GUID::new().unwrap();
    filter.displayData.name.0 = filter_name.as_mut_ptr();
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.action.r#type = FWP_ACTION_BLOCK;
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut condition;

    let mut filter2 = filter;
    filter2.filterKey = GUID::new().unwrap();
    filter2.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    _add_filter(engine_handle, filter);
    _add_filter(engine_handle, filter2);
    let app_id_ptr_ptr: *mut *mut c_void = &mut app_id as *mut _ as *mut *mut c_void;
    FwpmFreeMemory0(app_id_ptr_ptr);
    println!("final is reached!");
    FilterOnV4AndV6{
        filter1: filter,
        filter2
    }
}
// DB CONNECTION
pub fn db_connect() -> Connection {
    let connection = Connection::open("firewall.db")
        .expect("error while trying to connect to db!");
    connection
        .execute("create table if not exists blocked_apps (id integer primary key, guid text not null, name text not null, file_path text not null, action text not null)",())
        .expect("error while trying to create db!");
    connection
}
// MODELS
pub struct Filter{
    pub id: u16,
    pub guid: String,
    pub name: String,
    pub file_path: String,
    pub action: String
}

impl Filter {
    pub fn new(name: String, action: String, file_path: String, id: u16, guid:  *const GUID) -> Self{
        Self { 
            name ,
            action, 
            file_path, 
            id,
            guid: unsafe { 
                wchar_to_string(guid_to_string(guid)) 
            }
        }
    }
    pub fn from_db(name: String, action: String, file_path: String, id: u16, guid:  String) -> Self{
        Self { 
            name ,
            action, 
            file_path, 
            id,
            guid
        }
    }
    pub fn get_all(connection: &mut Connection) -> Vec<Self>{
        let mut prepared_query = connection
            .prepare("select id, guid, name, file_path, action from blocked_apps")
            .expect("unable to communicate to db!");
        let blocked_apps_iter = prepared_query
            .query_map([],|row: &Row<'_>|{
                Ok(Filter::from_db(
                    row.get(2)?,
                    row.get(4)?,
                    row.get(3)?,
                    row.get(0)?,
                    row.get(1)?))
            }).unwrap();
        blocked_apps_iter.map(|result| result.unwrap()).collect()
    }
    pub fn get_by_id(connection: &mut Connection, id: String) -> Self {
        let mut prepared_query = connection
            .prepare("select id, guid, name, action, file_path from blocked_apps where id = :id")
            .expect("connection with db cannot be stablished!");
        let filter_iter = prepared_query.query_map(&[(":id",id.as_str())], |row|
            {Ok(Filter::from_db(
                row.get(2)?,
                row.get(3)?,
                row.get(3)?,
                row.get(0)?,
                row.get(1)?
        ))}).unwrap();
        filter_iter.last().unwrap().unwrap()
    }
}
pub trait DAO {
    fn save( &self, connection: &mut Connection ) -> bool;
    fn delete( &self, connection: &mut Connection );
    fn update(&self, connection: &mut Connection);
}
impl DAO for Filter{
    fn save( &self, connection: &mut Connection ) -> bool {
        let conn_value = connection
            .execute(
                "insert into blocked_apps (name, file_path, guid, action) values (?1,?2,?3,?4)",
                params![self.name,self.file_path,self.guid,self.action]);
        match conn_value {
            Ok(_) => true,
            Err(_) => false
        }
    }
    fn delete( &self, connection: &mut Connection ){
        connection
            .execute("delete from blocked_apps where id= ?1", params![self.id])
            .expect("filter cannot be deleted problem in db!");
        // unsafe { _delete_filter(engine_handle, &mut GUID::from(reference.as_str())) }
    }
    fn update(&self, connection: &mut Connection) {
        connection
            .execute("update blocked_apps set guid = ?1 where id =?2", params![self.guid, self.id])
            .expect("filter cannot be updated!");
    }
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
pub unsafe fn block_app_once_on_startup(layer: &str, filter_name: &str, file_path: &str,engine_handle: HANDLE) -> GUID{
    let app_file_path = U16CString::from_str(file_path).unwrap();
    let mut filter_name_parsed = U16CString::from_str(filter_name).unwrap();
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut(); 
    let app_filename = PCWSTR(app_file_path.as_ptr());
    FwpmGetAppIdFromFileName0(app_filename, &mut app_id);
    if layer == "v6" {
        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.Anonymous.byteBlob = app_id;

        let mut wfp_filter = FWPM_FILTER0::default();
        wfp_filter.filterKey = GUID::new().unwrap();
        wfp_filter.displayData.name.0 = filter_name_parsed.as_mut_ptr();
        wfp_filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        wfp_filter.action.r#type = FWP_ACTION_BLOCK;
        wfp_filter.numFilterConditions = 1;
        wfp_filter.filterCondition = &mut condition;
        _add_filter(engine_handle, wfp_filter);
        let app_id_ptr_ptr: *mut *mut c_void = &mut app_id as *mut _ as *mut *mut c_void;
        FwpmFreeMemory0(app_id_ptr_ptr);
        wfp_filter.filterKey
    }else if layer == "v4"{
        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.Anonymous.byteBlob = app_id;

        let mut wfp_filter = FWPM_FILTER0::default();
        wfp_filter.filterKey = GUID::new().unwrap();
        wfp_filter.displayData.name.0 = filter_name_parsed.as_mut_ptr();
        wfp_filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        wfp_filter.action.r#type = FWP_ACTION_BLOCK;
        wfp_filter.numFilterConditions = 1;
        wfp_filter.filterCondition = &mut condition;
        _add_filter(engine_handle, wfp_filter);
        let app_id_ptr_ptr: *mut *mut c_void = &mut app_id as *mut _ as *mut *mut c_void;
        FwpmFreeMemory0(app_id_ptr_ptr);
        wfp_filter.filterKey

    }else{
        panic!("this layer does not exists or is not applied!");
    }

}