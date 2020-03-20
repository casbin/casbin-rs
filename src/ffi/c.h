// casbin c ffi header

struct Enforcer;
extern struct Enforcer* new_enforcer(char* conf_file, char* policy_file);
extern int enforce(struct Enforcer* enforcer, char *sub, char *obj, char *act);

// how to use this header, a demo ffi.c file

// #include <stdio.h>
// #include "c.h"

// int main() {
//     struct Enforcer* e = new_enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

//     int res1 = enforce(e, "alice", "data1", "read");
//     int res2 = enforce(e, "alice", "data1", "write");

//     printf("res1=%d\n", res1);
//     printf("res2=%d\n", res2);

//     return 0;
// }
