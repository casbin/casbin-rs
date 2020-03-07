use casbin::{DefaultModel, Enforcer, FileAdapter, MemoryAdapter, Model, RbacApi};
use criterion::{criterion_group, criterion_main, Criterion};
use async_std::task;

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
            let _e = task::block_on(Enforcer::new(Box::new(m), Box::new(adpt))).unwrap();
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
        let e = task::block_on(Enforcer::new(Box::new(m), Box::new(adapter))).unwrap();

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
        let mut e = task::block_on(Enforcer::new(Box::new(m), Box::new(adapter))).unwrap();

        b.iter(|| {
            task::block_on(e.add_permission_for_user("alice", vec!["data1", "read"]))
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
