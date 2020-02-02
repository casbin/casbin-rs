pub trait Watcher: Send + Sync {
    fn set_update_callback(&mut self, cb: Box<dyn FnMut() + Send + Sync + 'static>);
    fn update(&self);
}
