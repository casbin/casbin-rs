use casbin::{DefaultModel, Enforcer, FileAdapter, MemoryAdapter, Model, RbacApi};
use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "runtime-async-std")]
fn await_future<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    async_std::task::block_on(future)
}

#[cfg(feature = "runtime-tokio")]
fn await_future<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::runtime::Runtime::new().unwrap().block_on(future)
}
// To save a new baseline to compare against run
// `cargo bench -- --save-baseline <baseline name>`
// on the master branch.
//
// then to compare your changes switch to your branch and run
// `cargo bench -- --baseline <baseline name>`

fn default_model(b: &mut Criterion) {
    b.bench_function("crate instance of DefaultModel", |b| {
        b.iter(|| {
            let mut m = DefaultModel::default();
            m.add_def("r", "r", "sub, obj, act");
            m.add_def("p", "p", "sub, obj, act");
            m.add_def("e", "e", "some(where (p.eft == allow))");
            m.add_def(
                "m",
                "m",
                "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
            );
        });
    });
}

fn file_adapter(b: &mut Criterion) {
    b.bench_function("crate instance of FileAdapter", |b| {
        b.iter(|| {
            let _ = FileAdapter::new("examples/basic_model.conf");
        });
    });
}

fn enforcer_create(b: &mut Criterion) {
    b.bench_function("crate instance of Enforcer", |b| {
        b.iter(|| {
            // unfortunately there is no way to pass these in by value so we must
            // measure their creation
            let mut m = DefaultModel::default();
            m.add_def("r", "r", "sub, obj, act");
            m.add_def("p", "p", "sub, obj, act");
            m.add_def("e", "e", "some(where (p.eft == allow))");
            m.add_def(
                "m",
                "m",
                "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
            );
            let adpt = FileAdapter::new("examples/basic_model.conf");

            // what we want to measure
            let _e = await_future(Enforcer::new(Box::new(m), Box::new(adpt))).unwrap();
        });
    });
}

fn enforcer_enforce(b: &mut Criterion) {
    b.bench_function("enforces two permissions", |b| {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );
        let adapter = FileAdapter::new("examples/keymatch_policy.csv");
        let e = await_future(Enforcer::new(Box::new(m), Box::new(adapter))).unwrap();

        b.iter(|| {
            e.enforce(vec!["alice", "/alice_data/resource1", "GET"])
                .unwrap();
            e.enforce(vec!["alice", "/alice_data/resource1", "POST"])
                .unwrap();
        })
    });
}

fn enforcer_add_permission(b: &mut Criterion) {
    b.bench_function("adds permission for user MemoryAdapter", |b| {
        let mut m = DefaultModel::default();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("g", "g", "_, _");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        );

        let adapter = MemoryAdapter::default();
        let mut e = await_future(Enforcer::new(Box::new(m), Box::new(adapter))).unwrap();

        b.iter(|| {
            await_future(e.add_permission_for_user("alice", vec!["data1", "read"])).unwrap();
        })
    });
}

criterion_group!(
    benches,
    enforcer_create,
    enforcer_enforce,
    enforcer_add_permission,
    file_adapter,
    default_model
);
criterion_main!(benches);

#[allow(dead_code)]
mod task {
    use std::future::Future;
    use std::pin::Pin;
    use std::ptr;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    const RAW_WAKER: RawWaker = RawWaker::new(ptr::null(), &VTABLE);
    const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

    unsafe fn clone(_: *const ()) -> RawWaker {
        RAW_WAKER
    }

    unsafe fn wake(_: *const ()) {}

    unsafe fn wake_by_ref(_: *const ()) {}

    unsafe fn drop(_: *const ()) {}

    pub fn create() -> Waker {
        // Safety: The waker points to a vtable with functions that do nothing. Doing
        // is always safe.
        unsafe { Waker::from_raw(RAW_WAKER) }
    }

    pub fn block_on<F, T>(mut future: F) -> T
    where
        F: Future<Output = T>,
    {
        // Safety: since we own the future no one can move any part of it but us, and we won't.
        let mut fut = unsafe { Pin::new_unchecked(&mut future) };
        let waker = create();
        let mut ctx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(res) = fut.as_mut().poll(&mut ctx) {
                return res;
            }
            // TODO since criterion is single threaded simply looping seems ok
            // burning cpu for a simpler function seems fair
            // possible `std::sync::atomic::spin_loop_hint` here.
        }
    }
}
