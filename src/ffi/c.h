// casbin c ffi header

struct Enforcer;
struct Adapter;

extern struct Adapter *new_adapter(char *dsn);

// TODO: If we have a new adapter we must add a new declaration here, any better method?
extern struct Adapter *new_diesel_adapter(char *dsn);

extern struct Enforcer *new_enforcer(char *conf_file, struct Adapter *adapter_ptr);
extern int enforce(struct Enforcer *enforcer, char *sub, char *obj, char *act);

// RBAC APIs
extern char **get_roles_for_user(struct Enforcer *enforcer, char *name);

// how to use this header, a demo ffi.c file

// #include <stdio.h>
// #include "c.h"

// int main() {
//     // struct Adapter *adapter = new_diesel_adapter("postgres://username:passwd@127.0.0.1/database");
//     struct Adapter *adapter = new_adapter("examples/basic_policy.csv");
//     struct Enforcer *e = new_enforcer("examples/basic_model.conf", adapter);
//     int res1 = enforce(e, "alice", "data1", "read");
//     int res2 = enforce(e, "alice", "data1", "write");
//     printf("res1=%d\n", res1);
//     printf("res2=%d\n", res2);

//     // test rbac api
//     struct Adapter *adapter2 = new_adapter("examples/rbac_policy.csv");
//     struct Enforcer *e2 = new_enforcer("examples/rbac_model.conf", adapter2);
//     char **roles = get_roles_for_user(e2, "alice");
//     printf("%s\n", roles[0]);

//     return 0;
// }
