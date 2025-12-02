# Custom Functions in Casbin-RS

## Overview

Custom functions in Casbin-RS now support flexible argument types through Rhai's `Dynamic` type. This means you can create custom functions that work with:

- **Strings** (as `ImmutableString`)
- **Integers** (i32 or i64)
- **Booleans**
- **Floats** (f32 or f64)
- **Arrays**
- **Maps**
- And more...

This improvement addresses the limitation where custom functions previously only accepted `ImmutableString` arguments.

## Basic Usage

### Adding a Custom Function

Custom functions are added using the `add_function` method on an `Enforcer` instance:

```rust
use casbin::prelude::*;
use rhai::Dynamic;

// Create your enforcer
let mut e = Enforcer::new("model.conf", "policy.csv").await?;

// Add a custom function
e.add_function(
    "myFunction",
    OperatorFunction::Arg2(|arg1: Dynamic, arg2: Dynamic| {
        // Your custom logic here
        true.into() // Return a Dynamic value
    }),
);
```

## Examples

### 1. String-based Custom Function

For custom functions that work with strings, you can use the helper function `dynamic_to_str`:

```rust
use casbin::model::function_map::dynamic_to_str;

e.add_function(
    "stringContains",
    OperatorFunction::Arg2(|haystack: Dynamic, needle: Dynamic| {
        let haystack_str = dynamic_to_str(&haystack);
        let needle_str = dynamic_to_str(&needle);
        haystack_str.contains(needle_str.as_ref()).into()
    }),
);
```

Or simply convert to String:

```rust
e.add_function(
    "stringMatch",
    OperatorFunction::Arg2(|s1: Dynamic, s2: Dynamic| {
        let str1 = s1.to_string();
        let str2 = s2.to_string();
        (str1 == str2).into()
    }),
);
```

### 2. Integer-based Custom Function

```rust
e.add_function(
    "greaterThan",
    OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
        let a_int = a.as_int().unwrap_or(0);
        let b_int = b.as_int().unwrap_or(0);
        (a_int > b_int).into()
    }),
);
```

### 3. Boolean-based Custom Function

```rust
e.add_function(
    "customAnd",
    OperatorFunction::Arg2(|a: Dynamic, b: Dynamic| {
        let a_bool = a.as_bool().unwrap_or(false);
        let b_bool = b.as_bool().unwrap_or(false);
        (a_bool && b_bool).into()
    }),
);
```

### 4. Multi-argument Custom Function

```rust
e.add_function(
    "between",
    OperatorFunction::Arg3(|val: Dynamic, min: Dynamic, max: Dynamic| {
        let val_int = val.as_int().unwrap_or(0);
        let min_int = min.as_int().unwrap_or(0);
        let max_int = max.as_int().unwrap_or(0);
        (val_int >= min_int && val_int <= max_int).into()
    }),
);
```

### 5. Mixed-type Custom Function

```rust
e.add_function(
    "complexCheck",
    OperatorFunction::Arg3(|name: Dynamic, age: Dynamic, is_admin: Dynamic| {
        let name_str = name.to_string();
        let age_int = age.as_int().unwrap_or(0);
        let admin_bool = is_admin.as_bool().unwrap_or(false);
        
        // Custom logic with different types
        let result = name_str.len() > 3 && age_int >= 18 && admin_bool;
        result.into()
    }),
);
```

## Using Custom Functions in Matchers

Once registered, custom functions can be used in your policy matchers:

```conf
[matchers]
m = greaterThan(r.age, 18) && stringContains(r.path, p.path)
```

## OperatorFunction Variants

The `OperatorFunction` enum supports functions with 0 to 6 arguments. There are two types of variants:

### Function Pointer Variants (Stateless)

These use simple function pointers and cannot capture external state:

- `Arg0`: `fn() -> Dynamic`
- `Arg1`: `fn(Dynamic) -> Dynamic`
- `Arg2`: `fn(Dynamic, Dynamic) -> Dynamic`
- `Arg3`: `fn(Dynamic, Dynamic, Dynamic) -> Dynamic`
- `Arg4`: `fn(Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic`
- `Arg5`: `fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic`
- `Arg6`: `fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic`

### Closure Variants (Can Capture State)

These use `Arc<dyn Fn>` and can capture external state like database connections:

- `Arg0Closure`: `Arc<dyn Fn() -> Dynamic + Send + Sync>`
- `Arg1Closure`: `Arc<dyn Fn(Dynamic) -> Dynamic + Send + Sync>`
- `Arg2Closure`: `Arc<dyn Fn(Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg3Closure`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg4Closure`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg5Closure`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`
- `Arg6Closure`: `Arc<dyn Fn(Dynamic, Dynamic, Dynamic, Dynamic, Dynamic, Dynamic) -> Dynamic + Send + Sync>`

## Capturing External State with Closures

One of the key features of the closure variants is the ability to capture external state. This is useful when you need to access application state (like database connections) from within your custom functions.

### Example: Capturing Database Connection in Axum

```rust
use casbin::{CoreApi, Enforcer, OperatorFunction};
use rhai::Dynamic;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    db_connection: Arc<DatabaseConnection>,
    casbin_enforcer: Arc<Mutex<Enforcer>>,
}

impl AppState {
    async fn setup_enforcer_with_db_check(&mut self) {
        // Clone the Arc to capture it in the closure
        let db_conn = self.db_connection.clone();
        
        // Create a closure that captures the database connection
        let check_fn = Arc::new(move |product_id: Dynamic| {
            let product_id_int = product_id.as_int().unwrap_or(0);
            
            // Access the database connection from the captured state
            // Note: In real code, you'd need to handle async properly
            let has_storages = db_conn.check_product_has_storages(product_id_int);
            
            has_storages.into()
        });
        
        // Register the closure-based function
        if let Ok(mut enforcer) = self.casbin_enforcer.lock() {
            enforcer.add_function(
                "matchProductHasStorages",
                OperatorFunction::Arg1Closure(check_fn),
            );
        }
    }
}
```

### Example: Multi-Argument Closure with Shared State

```rust
use casbin::{CoreApi, Enforcer, OperatorFunction};
use rhai::Dynamic;
use std::sync::Arc;
use std::collections::HashMap;

// Simulate external configuration
let prefix_map: Arc<HashMap<String, String>> = Arc::new({
    let mut m = HashMap::new();
    m.insert("data1".to_string(), "/api/v1/".to_string());
    m.insert("data2".to_string(), "/api/v2/".to_string());
    m
});

// Clone for the closure
let prefix_clone = prefix_map.clone();

// Create a two-argument closure that uses the shared state
e.add_function(
    "customPathCheck",
    OperatorFunction::Arg2Closure(Arc::new(move |request_path: Dynamic, policy_resource: Dynamic| {
        let req_path = request_path.to_string();
        let policy_res = policy_resource.to_string();
        
        // Use the captured prefix_map to determine if paths match
        if let Some(prefix) = prefix_clone.get(&policy_res) {
            req_path.starts_with(prefix).into()
        } else {
            (req_path == policy_res).into()
        }
    })),
);
```

## Working with Dynamic Types

Rhai's `Dynamic` type provides several methods to extract values:

- `as_int()` - Extract as integer (returns `Result<i64, &str>`)
- `as_bool()` - Extract as boolean (returns `Result<bool, &str>`)
- `as_float()` - Extract as float (returns `Result<f64, &str>`)
- `is_string()` - Check if it's a string
- `into_immutable_string()` - Convert to ImmutableString (consumes the Dynamic)
- `to_string()` - Convert to String (works for any type)

## Backward Compatibility

All existing code continues to work. The change from `ImmutableString` to `Dynamic` is backward compatible because:

1. Strings are automatically converted to `Dynamic` by Rhai
2. The `dynamic_to_str` helper function makes string extraction easy
3. All built-in functions have been updated and tested

## Migration Guide

If you have existing custom functions using `ImmutableString`, update them like this:

**Before:**
```rust
e.add_function(
    "myFunc",
    OperatorFunction::Arg2(
        |s1: ImmutableString, s2: ImmutableString| {
            // logic here
            true.into()
        }
    ),
);
```

**After:**
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

## See Also

- [Casbin Documentation](https://casbin.org/docs/function)
- [Rhai Documentation](https://rhai.rs/book/)
- Test: `test_custom_function_with_dynamic_types` in `src/enforcer.rs`
