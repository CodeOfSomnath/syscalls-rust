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

using Cargo.toml

```toml
[dependencies.syscalls-rust]
version = "0.2.2" # latest version
features = ["arch64"] # This is the support for 64 bit systems
```

# Features

There are only available feature is 'x64_86'

You can add the features using Cargo.toml file:

```toml
[dependencies.syscalls-rust]
version = "0.2.2" # latest version
features = ["arch64"] # This is the support for 64 bit systems
```


## Cargo.toml

Well You can see Cargo.toml and check yourself which features is now available

<!-- update this every time cargo.toml update -->

```toml
[package]
name = "syscalls-rust"
license = "GPL-3.0-only"
readme = "README.md"
description = "Linux syscalls for rust"
keywords = ["linux", "syscalls", "c", "kernel"]
repository = "https://github.com/CodeOfSomnath/linux-syscalls"
version = "0.2.2"
edition = "2024"



[features]
# This features are defined for different architecture.
# if any arch I have missed then raise a issue and tell me about it
default = ["arch64"]
arch32 = [] # x86 64 bit, x32 abi
arch64 = [] # x86 64 bit, x86-64 abi
arm64 = [] # Arm 64 bit, Arch 64 bit
arm32 = [] # Arm 64 bit, Arch 32 bit


[dependencies]

```


## Contribution

If you want to contribute to this project you are welcome.<br>
You can make a pull request to contribute to this library.

