use crate::{Adapter, DefaultModel, Enforcer, FileAdapter, RbacApi};
use async_std::task::block_on;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn new_adapter(dsn: *const c_char) -> Box<dyn Adapter> {
    let dsn = unsafe { CStr::from_ptr(dsn) };
    let adapter = FileAdapter::new(dsn.to_str().unwrap());

    Box::new(adapter)
}

#[no_mangle]
pub extern "C" fn new_enforcer(
    conf_file: *const c_char,
    adapter_ptr: *mut dyn Adapter,
) -> Box<Enforcer> {
    let conf_file = unsafe { CStr::from_ptr(conf_file) };
    let m = block_on(DefaultModel::from_file(conf_file.to_str().unwrap())).unwrap();

    // let adapter = new_adapter(dsn);
    let adapter = unsafe { Box::from_raw(adapter_ptr) };
    let e = block_on(Enforcer::new(Box::new(m), adapter)).unwrap();

    Box::new(e)
}

#[no_mangle]
pub extern "C" fn enforce(
    enforcer: &mut Enforcer,
    sub: *const c_char,
    obj: *const c_char,
    act: *const c_char,
) -> bool {
    let sub = unsafe { CStr::from_ptr(sub) };
    let obj = unsafe { CStr::from_ptr(obj) };
    let act = unsafe { CStr::from_ptr(act) };
    enforcer
        .enforce(vec![
            sub.to_str().unwrap(),
            obj.to_str().unwrap(),
            act.to_str().unwrap(),
        ])
        .unwrap()
}

#[no_mangle]
pub extern "C" fn get_roles_for_user(
    enforcer: &mut Enforcer,
    name: *const c_char,
) -> *const *const c_char {
    let name = unsafe { CStr::from_ptr(name) };
    let rs_name = name.to_str().unwrap();
    let roles = enforcer.get_roles_for_user(rs_name, None);

    let v: Vec<*const c_char> = roles
        .iter()
        .map(|role| CString::new(role.as_str()).unwrap().as_ptr())
        .collect();
    v.as_ptr()
}
