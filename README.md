## Linux Syscalls 
This is the library for linux syscalls all are the signatures and data types.

## License
This library is licensed under the gpl-3.0 license. So you can use this library
and use it under the conditions of gpl-3.0 license.

## Install

Using cargo 

```bash
cargo add syscalls-rust
```
or<br>

using cargo.toml

```toml

[dependencies.syscalls-rust]
version = "0.1.5" # latest version
features = ["x64_86"] # This is the support for 64 bit systems
```

# Features

There are only available feature is 'x64_86'

You can add the features using Cargo.toml file:

```toml

[dependencies.syscalls-rust]
version = "0.1.5" # latest version
features = ["x64_86"] # This is the support for 64 bit systems
```


## Cargo.toml

Well You can see Cargo.toml and check yourself which features is now available

<!-- update this every time cargo.toml update -->

```toml
[package]
name = "syscalls-rust"
license-file = "LICENSE"
readme = "README.md"
description = "Linux syscalls for rust"
keywords = ["linux", "syscalls", "c", "kernel"]
repository = "https://github.com/CodeOfSomnath/linux-syscalls"
version = "0.1.5"
edition = "2024"



[features]
default = ["x64_86"]
x64_86 = []

[dependencies]

```


## Contribution

If you want to contribute to this project you are welcome.<br>
You can make a pull request to contribute to this library.

