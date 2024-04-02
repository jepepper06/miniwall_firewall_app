use rusqlite::{params, Connection, Row};
use windows::core::GUID;

use super::{guid_to_string, wchar_to_string};

// DB CONNECTION
pub fn db_connect() -> Connection {
    let connection = Connection::open("firewall.db")
        .expect("error while trying to connect to db!");
    connection
        .execute("create table if not exists app_filters (id integer primary key, guid text not null, name text not null, file_path text not null, action text not null)",())
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
    #[allow(dead_code)]
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
            .prepare("select id, guid, name, file_path, action from app_filters")
            .expect("unable to communicate to db!");
        let app_filters_iter = prepared_query
            .query_map([],|row: &Row<'_>|{
                Ok(Filter::from_db(
                    row.get(2)?,
                    row.get(4)?,
                    row.get(3)?,
                    row.get(0)?,
                    row.get(1)?))
            }).unwrap();
        app_filters_iter.map(|result| result.unwrap()).collect()
    }
    #[allow(dead_code)]
    pub fn get_by_id(connection: &mut Connection, id: String) -> Self {
        let mut prepared_query = connection
            .prepare("select id, guid, name, action, file_path from app_filters where id = :id")
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
    #[allow(dead_code)]
    pub fn get_by_file_path(connection: &mut Connection, file_path: String) -> Vec<Self> {
        let mut prepared_query = connection
        .prepare("select id, guid, name, action, file_path from app_filters where file_path = :file_path")
        .expect("connection with db cannot be stablished!");
    let filter_iter = prepared_query.query_map(&[(":file_path",file_path.as_str())], |row|
        {Ok(Filter::from_db(
            row.get(2)?,
            row.get(3)?,
            row.get(3)?,
            row.get(0)?,
            row.get(1)?
    ))}).unwrap();
    println!("function executed");
    let filters: Result<Vec<_>, _> = filter_iter.collect();

    filters.unwrap()
    }
    #[allow(dead_code)]
    pub fn delete_all(connection: &Connection){
        connection
            .execute("delete from app_filters",[])
            .expect("error while deleting all filters!");
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
                "insert into app_filters (name, file_path, guid, action) values (?1,?2,?3,?4)",
                params![self.name,self.file_path,self.guid,self.action]);
        match conn_value {
            Ok(_) => true,
            Err(_) => false
        }
    }
    fn delete( &self, connection: &mut Connection ){
        connection
            .execute("delete from app_filters where id= ?1", params![self.id])
            .expect("filter cannot be deleted problem in db!");
        // unsafe { _delete_filter(engine_handle, &mut GUID::from(reference.as_str())) }
    }
    fn update(&self, connection: &mut Connection) {
        connection
            .execute("update app_filters set guid = ?1 where id =?2", params![self.guid, self.id])
            .expect("filter cannot be updated!");
    }
}