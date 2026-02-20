# uDSN

A quick little DSN parser that can give you a nice looking URI connection string on the other side:

```rust
use udsn::{DSN, Resource};

let dsn = DSN::new(
    "postgres".to_string(),     // protocol
    None,                       // username
    None,                       // password
    Resource::URI("localhost"), // uri or localpath
    Some(5432),                 // port
    Some("db_name"),            // dbname
    Some(vec![                  // params
        ("sslmode",         Some("verify")),
        ("connect_timeout", Some("10"))
    ]),
);

dsn.to_string() == "postgresql://localhost/db?sslmode=verify-full&connect_timeout=10";

/* OR, parse and modify an existing */

let dsn = DSN::parse("postgresql://localhost/db?sslmode=verify-full&connect_timeout=10");

dsn.username = Some("user");
dsn.password = Some("pass");

dsn.to_string() == "postgresql://user:pass@localhost/db?sslmode=verify-full&connect_timeout=10";

/* as a bonus you can also use the percent encoder/decoder */

use udsn::{percent_encode, percent_decode};

percent_encode("/...") == "%2f...";
percent_decode("%2f...") == "/...";

```

# Motivation

The motiviation for writing this module is that other DSN modules had various bugs, dependencies, or other weirdness.
The most common being that odd characters would show up when using parameters (or no parameters) and upon looking
at the tests, they tested the one use case they needed the module for. Or, they provided no documentation/examples.

So, here we are.
