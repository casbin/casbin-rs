use crate::{DefaultModel, Enforcer, FileAdapter};
use async_std::task::block_on;
use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn new_enforcer(
    conf_file: *const c_char,
    policy_file: *const c_char,
) -> Box<Enforcer> {
    let conf_file = unsafe { CStr::from_ptr(conf_file) };
    let m = block_on(DefaultModel::from_file(conf_file.to_str().unwrap())).unwrap();

    let policy_file = unsafe { CStr::from_ptr(policy_file) };
    let adapter = FileAdapter::new(policy_file.to_str().unwrap());
    let e = block_on(Enforcer::new(Box::new(m), Box::new(adapter))).unwrap();

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
