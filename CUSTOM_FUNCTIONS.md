# Custom Functions in Casbin-RS

## Overview

Custom functions in Casbin-RS support flexible argument types through Rhai's `Dynamic` type and can capture external state. This means you can create custom functions that:

- Work with **Strings** (as `ImmutableString`)
- Work with **Integers** (i32 or i64)
- Work with **Booleans**
- Work with **Floats** (f32 or f64)
- Work with **Arrays** and **Maps**
- **Capture external state** like database connections, configuration, or shared data

## Basic Usage

### Adding a Custom Function

Custom functions are added using the `add_function` method on an `Enforcer` instance. Functions are wrapped in `Arc::new()` to support cloning and thread-safety:

```rust
use casbin::prelude::*;
use rhai::Dynamic;
use std::sync::Arc;

// Create your enforcer
let mut e = Enforcer::new("model.conf", "policy.csv").await?;

// Add a custom function
e.add_function(
    "myFunction",
    OperatorFunction::Arg2(Arc::new(|arg1: Dynamic, arg2: Dynamic| {
        // Your custom logic here
        true.into() // Return a Dynamic value
    })),
);
```

## Examples

### 1. String-based Custom Function

For custom functions that work with strings, you can use the helper function `dynamic_to_str`:

```rust
use casbin::model::function_map::dynamic_to_str;
use std::sync::Arc;

e.add_function(
    "stringContains",
    OperatorFunction::Arg2(Arc::new(|haystack: Dynamic, needle: Dynamic| {
        let haystack_str = dynamic_to_str(&haystack);
        let needle_str = dynamic_to_str(&needle);
        haystack_str.contains(needle_str.as_ref()).into()
    })),
);
```

Or simply convert to String:

```rust
use std::sync::Arc;

e.add_function(
    "stringMatch",
    OperatorFunction::Arg2(Arc::new(|s1: Dynamic, s2: Dynamic| {
        let str1 = s1.to_string();
        let str2 = s2.to_string();
        (str1 == str2).into()
    })),
);
```

### 2. Integer-based Custom Function

```rust
use std::sync::Arc;

e.add_function(
    "greaterThan",
    OperatorFunction::Arg2(Arc::new(|a: Dynamic, b: Dynamic| {
        let a_int = a.as_int().unwrap_or(0);
        let b_int = b.as_int().unwrap_or(0);
        (a_int > b_int).into()
    })),
);
```

### 3. Boolean-based Custom Function

```rust
use std::sync::Arc;

e.add_function(
    "customAnd",
    OperatorFunction::Arg2(Arc::new(|a: Dynamic, b: Dynamic| {
        let a_bool = a.as_bool().unwrap_or(false);
        let b_bool = b.as_bool().unwrap_or(false);
        (a_bool && b_bool).into()
    })),
);
```

### 4. Multi-argument Custom Function

```rust
use std::sync::Arc;

e.add_function(
    "between",
    OperatorFunction::Arg3(Arc::new(|val: Dynamic, min: Dynamic, max: Dynamic| {
        let val_int = val.as_int().unwrap_or(0);
        let min_int = min.as_int().unwrap_or(0);
        let max_int = max.as_int().unwrap_or(0);
        (val_int >= min_int && val_int <= max_int).into()
    })),
);
```

### 5. Mixed-type Custom Function

```rust
use std::sync::Arc;

e.add_function(
    "complexCheck",
    OperatorFunction::Arg3(Arc::new(|name: Dynamic, age: Dynamic, is_admin: Dynamic| {
        let name_str = name.to_string();
        let age_int = age.as_int().unwrap_or(0);
        let admin_bool = is_admin.as_bool().unwrap_or(false);
        
        // Custom logic with different types
        let result = name_str.len() > 3 && age_int >= 18 && admin_bool;
        result.into()
    })),
);
```

### 6. Capturing External State (Database Connection, etc.)

One of the key features is the ability to capture external state in custom functions. This is useful for accessing database connections, configuration, or any shared data:

```rust
use std::sync::Arc;

// Example: Using with a database connection pool
// This could be r2d2, deadpool, bb8, or any other connection pool
struct AppState {
    // db_pool: Pool<SqliteConnectionManager>,
    allowed_resources: Vec<i32>,
}

let app_state = Arc::new(AppState {
    allowed_resources: vec![1, 2, 3, 5, 8],
});

// Clone the Arc to move into the closure
let state_clone = app_state.clone();

e.add_function(
    "checkResourceAccess",
    OperatorFunction::Arg1(Arc::new(move |resource_id: Dynamic| {
        let id = resource_id.as_int().unwrap_or(0) as i32;
        // Access the captured state
        state_clone.allowed_resources.contains(&id).into()
    })),
);
```

#### Real-world Example with r2d2 Connection Pool

```rust
use r2d2::{self, Pool};
use r2d2_sqlite::SqliteConnectionManager;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct AppState {
    db_pool: Pool<SqliteConnectionManager>,
    casbin_enforcer: Arc<Mutex<Enforcer>>,
}

impl AppState {
    fn create_storage_check_function(&self) -> OperatorFunction {
        let pool = self.db_pool.clone();
        
        OperatorFunction::Arg1(Arc::new(move |product_id: Dynamic| {
            let product_id_int = product_id.as_int().unwrap_or(0) as i64;
            
            // Get a connection from the pool
            let conn = pool.get().expect("Failed to get connection");
            
            // Query the database
            let has_storage: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM storages WHERE product_id = ?)",
                    [product_id_int],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            
            has_storage.into()
        }))
    }
}

// Usage (assuming app_state is already constructed):
// let app_state: AppState = /* your initialization */;
let check_fn = app_state.create_storage_check_function();
enforcer.add_function("matchProductHasStorages", check_fn);
```

## Using Custom Functions in Matchers

Once registered, custom functions can be used in your policy matchers:

```conf
[matchers]
m = greaterThan(r.age, 18) && stringContains(r.path, p.path)
```

Or with captured state:

```conf
[matchers]
m = r.sub == p.sub && checkResourceAccess(r.resource_id)
```

## OperatorFunction Variants

The `OperatorFunction` enum supports functions with 0 to 6 arguments. Each variant wraps an `Arc<dyn Fn>`:

- `Arg0`: `Arc<dyn Fn() -> Dynamic + Send + Sync>`
- `Arg1`: `Arc<dyn Fn(Dynamic) -> Dynamic + Send + Sync>`
- `Arg2`: `Arc<dyn Fn(Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg3`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg4`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg5`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg6`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`

## Working with Dynamic Types

Rhai's `Dynamic` type provides several methods to extract values:

- `as_int()` - Extract as integer (returns `Result<i64, &str>`)
- `as_bool()` - Extract as boolean (returns `Result<bool, &str>`)
- `as_float()` - Extract as float (returns `Result<f64, &str>`)
- `is_string()` - Check if it's a string
- `into_immutable_string()` - Convert to ImmutableString (consumes the Dynamic)
- `to_string()` - Convert to String (works for any type)

## Migration Guide

If you have existing custom functions, update them to wrap closures with `Arc::new()`:

**Before:**
```rust
e.add_function(
    "myFunc",
    OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
        let str1 = s1.to_string();
        let str2 = s2.to_string();
        // logic here
        true.into()
    }),
);
```

**After:**
```rust
use std::sync::Arc;

e.add_function(
    "myFunc",
    OperatorFunction::Arg2(Arc::new(|s1: Dynamic, s2: Dynamic| {
        let str1 = s1.to_string();
        let str2 = s2.to_string();
        // logic here
        true.into()
    })),
);
```

## See Also

- [Casbin Documentation](https://casbin.org/docs/function)
- [Rhai Documentation](https://rhai.rs/book/)
- Tests in `src/enforcer.rs`:
  - `test_custom_function_with_dynamic_types`
  - `test_custom_function_with_captured_state`
