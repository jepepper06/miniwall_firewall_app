use libc::c_void;
use widestring::U16CString;
use windows::{core::{GUID, PCWSTR}, Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::{FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL}, System::Rpc::RPC_C_AUTHN_WINNT}};

// WFP ABSTRACTIONS OVER WINDOWS CRATE
pub unsafe fn initialize_filtering_engine(borrowed_handle: &mut HANDLE) {
    let result = FwpmEngineOpen0(
        None,
        RPC_C_AUTHN_WINNT,
        None,
        None,
        borrowed_handle,
    );
    if result != 0 {
        panic!("filtering engine couldn't be initialized!")
    }
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
#[allow(dead_code)]
pub unsafe fn create_enum_handle(engine_handle: HANDLE,enum_handle_pointer: &mut HANDLE){
    let result = FwpmFilterCreateEnumHandle0(engine_handle, None, enum_handle_pointer);
    if result != 0 {
        close_filtering_engine(engine_handle);
        panic!("error while enumerating filters!");
    }
}
#[allow(dead_code)]
pub unsafe fn destroy_enum_handle(engine_handle: HANDLE, enum_handle: HANDLE){
    let result = FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
    if result != 0 {
        close_filtering_engine(engine_handle);
        panic!("error while enumerating filters!");
    }
}
#[allow(dead_code)]
pub unsafe fn filter_enum(engine_handle: HANDLE,enum_handle: HANDLE,count: *mut u32,filters: *mut *mut *mut FWPM_FILTER0){
    let result = FwpmFilterEnum0(engine_handle, enum_handle,8192,filters,count);
    if result != 0 {
        close_filtering_engine(engine_handle);
        panic!("error while enumerating filters!");
    }
}
#[allow(dead_code)]
pub unsafe fn free_filters_memory(mut filters: *mut *mut *mut FWPM_FILTER0){
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
        close_filtering_engine(engine_handle);
        panic!("the filter could not be added!")
    }
}
pub unsafe fn _delete_filter(engine_handle: HANDLE,guid: &mut GUID){
    let result = FwpmFilterDeleteByKey0(engine_handle, guid);
    if result != 0 {
        close_filtering_engine(engine_handle);
        panic!("error while deleting the filter!");
    }
}
#[allow(dead_code)]
pub struct FilterOnV6AndV4{
    pub filter1: FWPM_FILTER0,
    pub filter2: FWPM_FILTER0
}

pub unsafe fn _block_app(engine_handle: HANDLE,filter_name: &str, filename: &str) -> FilterOnV6AndV4 {
    let mut filter_name_on_v6 = U16CString::from_str(Layer::V6.to_filter_name(filter_name)).unwrap();
    let mut filter_name_on_v4 = U16CString::from_str(Layer::V4.to_filter_name(filter_name)).unwrap();
    let app_filename_path = U16CString::from_str(filename).unwrap();
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let app_filename = PCWSTR(app_filename_path.as_ptr());  
    let get_app_id_from_filename = FwpmGetAppIdFromFileName0(app_filename, &mut app_id);  if get_app_id_from_filename != 0 {        close_filtering_engine(engine_handle);      panic!("the app id is not retrieved successfully!");  }
    
    let mut condition = FWPM_FILTER_CONDITION0::default();
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.Anonymous.byteBlob = app_id;

    let mut filter = FWPM_FILTER0::default();
    filter.filterKey = GUID::new().unwrap();

    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.displayData.name.0 = filter_name_on_v6.as_mut_ptr();
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.action.r#type = FWP_ACTION_BLOCK;
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut condition;

    let mut filter2 = filter;
    filter2.displayData.name.0 = filter_name_on_v4.as_mut_ptr();
    filter2.filterKey = GUID::new().unwrap();
    filter2.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    _add_filter(engine_handle, filter);
    _add_filter(engine_handle, filter2);
    let app_id_ptr_ptr: *mut *mut c_void = &mut app_id as *mut _ as *mut *mut c_void;
    FwpmFreeMemory0(app_id_ptr_ptr);
    println!("final is reached!");
    FilterOnV6AndV4{
        filter1: filter,
        filter2
    }
}
#[derive(PartialEq)]
pub enum Layer{
    V4,
    V6
}
impl Layer{
    #[allow(dead_code)]
    pub fn to_str(&self) -> &str{
        match self {
            Layer::V4 => "on-v4-connect-layer",
            Layer::V6 => "on-v6-connect-layer",
        }
    }
    #[allow(dead_code)]
    pub fn to_filter_name(&self, filter_name: &str) -> String {
        match self {
            Layer::V4 => format!("{} {}",filter_name,self.to_str()),
            Layer::V6 => format!("{} {}",filter_name,self.to_str())
        }
    }
}
#[allow(dead_code)]
pub fn create_allow_app_filters(filename: &str, filter_name: &str, engine_handle: HANDLE) -> FilterOnV6AndV4{
    let filter_on_v4_layer = create_allow_app_filter_on_v4_layer(filename, filter_name, engine_handle);
    let filter_on_v6_layer = create_allow_app_filter_on_v6_layer(filename, filter_name, engine_handle);
    FilterOnV6AndV4 { filter1: filter_on_v6_layer, filter2: filter_on_v4_layer}
}
#[allow(dead_code)]
pub fn create_allow_app_filter_on_v4_layer(filename: &str, filter_name: &str, engine_handle: HANDLE) -> FWPM_FILTER0 {
    let mut filter_name_on_v4 = U16CString::from_str(Layer::V4.to_filter_name(filter_name)).unwrap();
    let app_filename_path = U16CString::from_str(filename).unwrap();
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let app_filename = PCWSTR(app_filename_path.as_ptr());  
    let get_app_id_from_filename = unsafe { FwpmGetAppIdFromFileName0(app_filename, &mut app_id) };  if get_app_id_from_filename != 0 {        unsafe { close_filtering_engine(engine_handle) };      panic!("the app id is not retrieved successfully!");  }
    
    let mut condition = FWPM_FILTER_CONDITION0::default();
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.Anonymous.byteBlob = app_id;

    let mut filter = FWPM_FILTER0::default();
    filter.filterKey = GUID::new().unwrap();

    filter.displayData.name.0 = filter_name_on_v4.as_mut_ptr();
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.action.r#type = FWP_ACTION_PERMIT;
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut condition;
    filter
}
#[allow(dead_code)]
pub fn create_allow_app_filter_on_v6_layer(filename: &str, filter_name: &str, engine_handle: HANDLE) -> FWPM_FILTER0 {
    let mut filter_name_on_v6 = U16CString::from_str(Layer::V6.to_filter_name(filter_name)).unwrap();
    let app_filename_path = U16CString::from_str(filename).unwrap();
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let app_filename = PCWSTR(app_filename_path.as_ptr());  
    let get_app_id_from_filename = unsafe { FwpmGetAppIdFromFileName0(app_filename, &mut app_id) };  if get_app_id_from_filename != 0 {        unsafe { close_filtering_engine(engine_handle) };      panic!("the app id is not retrieved successfully!");  }
    
    let mut condition = FWPM_FILTER_CONDITION0::default();
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.Anonymous.byteBlob = app_id;

    let mut filter = FWPM_FILTER0::default();
    filter.filterKey = GUID::new().unwrap();

    filter.displayData.name.0 = filter_name_on_v6.as_mut_ptr();
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.r#type = FWP_ACTION_PERMIT;
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut condition;
    filter
}
