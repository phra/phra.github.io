---
layout: default
---

_**Jul 9, 2019**_

# Introducing Rustbuster — A Comprehensive Web Fuzzer and Content Discovery Tool

I decided to learn [The Rust Programming Language](https://doc.rust-lang.org/book/) and I ended up writing a _yet another web fuzzer and content discovery tool™_, but comprehensive of the main features from [DirBuster](https://sourceforge.net/projects/dirbuster/), [Gobuster](https://github.com/OJ/gobuster), [wfuzz](https://github.com/xmendez/wfuzz), [Patator's http_fuzz](https://github.com/lanjelot/patator) and [IIS Short Name Scanner](https://github.com/irsdl/IIS-ShortName-Scanner).

## Motivation

Rust is an amazing systems programming language. It features powerful and innovative ideas to provide what I like to define as a _higher low level language_.

The best aspects are:

- **it's compiled**: its toolchain is based on [LLVM](https://llvm.org/)
- **it's strong typed**: everything is strongly typed, providing by default a powerful linter and autocompletion tool.
- **it's very fast**: check [some benchmarks](https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/rust-go.html) versus [Go](https://golang.org/)
- **it has no runtime**: by design, Rust doesn't depends on any runtime
- **it has no garbage collector**: the innovative [ownership concept](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) let make it possible to have a programming language that doesn't force the developer to explicitly manage the memory while not not depending on a dedicated garbage collector

If you are interested in learning the language, check out [The Rust Programming Language book](https://doc.rust-lang.org/book/).

## Modules

### `dir` — Directories and files enumeration mode

_LOREM IPSUM_

### `dns` — A/AAAA DNS entries enumeration mode

_LOREM IPSUM_

### `vhost` — Virtual hosts enumeration mode

_LOREM IPSUM_

### `fuzz` — Custom fuzzing enumeration mode

_LOREM IPSUM_

### `tilde` — IIS 8.3 shortname enumeration mode

_LOREM IPSUM_

## Installation

You can grab the latest prebuilt binary from [GitHub](https://github.com/phra/rustbuster/releases).

At the moment I am only providing a `x86_64-unknown-linux-gnu` build. If you need it for a different architecture or operating system, you can find how to build it from the sources below.

This following function will do the trick:

```bash
install_rustbuster() {
    echo "Installing latest version of Rustbuster"
    latest_version=`curl -s https://github.com/phra/rustbuster/releases | grep "rustbuster-v" | head -n1 | cut -d'/' -f6`
    echo "Latest release: $latest_version"
    mkdir -p /opt/rustbuster
    wget -qP /opt/rustbuster https://github.com/phra/rustbuster/releases/download/$latest_version/rustbuster-$latest_version-x86_64-unknown-linux-gnu
    ln -fs /opt/rustbuster/rustbuster-$latest_version-x86_64-unknown-linux-gnu /opt/rustbuster/rustbuster
    chmod +x /opt/rustbuster/rustbuster
    echo "Done! Try running"
    echo "/opt/rustbuster/rustbuster -h"
}

install_rustbuster
```

## Hack it

In order to compile it from the sources we first need to install the [Rust toolchain](https://rustup.rs/).

By being a conventional Rust project, all the development flow is managed by [Cargo, the Rust package manager](https://doc.rust-lang.org/cargo/).

### Getting the source

You can grab the latest `master` branch hosted on [GitHub](https://github.com/phra/rustbuster) using `git`:

```text
git clone https://github.com/phra/rustbuster.git
```

### Development build

To produce a debug version of the binary, we can issue the following command in the root directory of the project:

```text
cargo build
```

### Release build

When everything is ready, we can generate an optimized binary and strip the remaining symbols with the following command:

```text
cargo build --release && strip target/release/rustbuster
```

### Running tests

Few tests are included at the moment. To run them you can use the following command:

```text
cargo test
```

### Running benches

Also few benches are included. To run them use:

```text
cargo bench
```

### Contributing to the project

[PRs are warmly welcome! ❤](https://github.com/phra/rustbuster/fork)

Contributions are not only welcome, but encouraged! Feel free to mess with the codebase and open a pull request on [GitHub](https://github.com/phra/rustbuster/pulls) with fixes, refactors and new features.

### Bonus: CircleCI integration

Are you interested in integrating a CI pipeline in a Rust project? I wrote a generic [CircleCI configuration](https://github.com/phra/rustbuster/blob/master/.circleci/config.yml) for Rust projects that you can reuse with yours. See it in action [here](https://circleci.com/gh/phra/workflows/rustbuster/tree/master).

[back](../)
