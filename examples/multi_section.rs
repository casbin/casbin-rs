use casbin::prelude::*;
use casbin::EnforceContext;

#[cfg(feature = "runtime-async-std")]
#[async_std::main]
async fn main() -> Result<()> {
    run_example().await
}

#[cfg(feature = "runtime-tokio")]
#[tokio::main]
async fn main() -> Result<()> {
    run_example().await
}

#[cfg(all(not(feature = "runtime-async-std"), not(feature = "runtime-tokio")))]
fn main() {}

async fn run_example() -> Result<()> {
    // Initialize the enforcer with multi-section model and policy
    let e = Enforcer::new(
        "examples/multi_section_model.conf",
        "examples/multi_section_policy.csv",
    )
    .await?;

    println!("Multiple Section Types Example");
    println!("===============================\n");

    // This model has two sections:
    // - Section 1 (default): r, p, e, m, g - for normal access control (sub, act, obj)
    // - Section 2: r2, p2, e2, m2, g2 - for simplified access control (sub, act)

    println!("Testing Section 1 (default) - with object:");
    println!("-------------------------------------------");

    // Test Section 1: alice has 'admin' action on project1, and 'admin' has 'read' permission
    // Policy: p, alice, admin, project1 -> alice is assigned 'admin' on project1  
    // Role: g, admin, read -> 'admin' role has 'read' permission
    // Matcher checks: alice == alice && g(admin, read) && project1 == project1
    let result = e.enforce(("alice", "read", "project1"))?;
    println!("alice can read project1: {}", result);
    assert_eq!(true, result);

    // alice has 'admin' action which also has 'write' permission
    // Role: g, admin, write -> 'admin' role has 'write' permission
    let result = e.enforce(("alice", "write", "project1"))?;
    println!("alice can write project1: {}", result);
    assert_eq!(true, result);

    // bob has 'user' action which only has 'read' permission, not 'write'
    // Policy: p, bob, user, project2
    // Role: g, user, read -> 'user' role has 'read' permission only
    let result = e.enforce(("bob", "read", "project2"))?;
    println!("bob can read project2: {}", result);
    assert_eq!(true, result);

    let result = e.enforce(("bob", "write", "project2"))?;
    println!("bob can write project2: {}", result);
    assert_eq!(false, result);

    println!("\nTesting Section 2 - without object:");
    println!("------------------------------------");

    // Test Section 2: james can execute
    // p2, james, execute -> james has execute permission
    // Use EnforceContext to specify which section to use
    let ctx = EnforceContext::new("2");
    let result = e.enforce_with_context(ctx, ("james", "execute"))?;
    println!("james can execute: {}", result);
    assert_eq!(true, result);

    // Test Section 2: alice doesn't have execute permission in section 2
    let ctx = EnforceContext::new("2");
    let result = e.enforce_with_context(ctx, ("alice", "execute"))?;
    println!("alice can execute: {}", result);
    assert_eq!(false, result);

    println!("\nAll tests passed! ✓");
    println!("\nThis demonstrates how multiple section types allow you to have");
    println!("different access control models in the same configuration:");
    println!("- Section 1: Three-parameter model (subject, action, object)");
    println!("- Section 2: Two-parameter model (subject, action)");

    Ok(())
}
