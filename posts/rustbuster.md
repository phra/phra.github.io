---
layout: default
---

_**Jul 11, 2019**_

# Introducing Rustbuster — A Comprehensive Web Fuzzer and Content Discovery Tool

I decided to learn [The Rust Programming Language](https://doc.rust-lang.org/book/) and I ended up writing [Rustbuster](https://github.com/phra/rustbuster), _yet another web fuzzer and content discovery tool™_, but comprehensive of the main features from [DirBuster](https://sourceforge.net/projects/dirbuster/), [Gobuster](https://github.com/OJ/gobuster), [wfuzz](https://github.com/xmendez/wfuzz), [Patator's http_fuzz](https://github.com/lanjelot/patator) and [IIS Short Name Scanner](https://github.com/irsdl/IIS-ShortName-Scanner).

## Motivation

Rust is an amazing systems programming language. It features powerful and innovative ideas to provide what I like to define as a _higher low level language_.

The best aspects are:

- **it's compiled**: its [toolchain](https://github.com/rust-lang/rustc-guide) is based on [LLVM](https://llvm.org/)
- **it's strong typed**: everything is [strongly typed](https://doc.rust-lang.org/book/ch03-02-data-types.html), providing by default a powerful [linter](https://github.com/rust-lang/rust-clippy) and [autocompletion](https://github.com/racer-rust/racer) tool
- **it's very fast**: check [some benchmarks](https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/rust-go.html) versus [Go](https://golang.org/)
- **it's safe**: [Rust is safe! ..or explicitly unsafe :)](https://doc.rust-lang.org/nomicon/meet-safe-and-unsafe.html)
- **it has no runtime**: by design, Rust doesn't depends on any [runtime](https://github.com/rust-lang/rust/blob/master/src/libstd/rt.rs)
- **it has no garbage collector**: the innovative [ownership concept](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) makes possible to not depend on a garbage collector while not having the responsability of manually managing the memory allocations on the heap

If you are interested into learning the language, check out [The Rust Programming Language book](https://doc.rust-lang.org/book/).

## Rustbuster

Rustbuster was started as a Rust playground project with [@ps1dr3x](https://twitter.com/ps1dr3x) with the goal of reimplement a [DirBuster](https://sourceforge.net/projects/dirbuster/) equivalent. It ended up by becoming a collection of modules useful in different situation. Having a single executable suitable for most common web fuzzing tasks is very handy. At the time of writing, there are five modules available, that are: `dir`, `dns`, `vhost`, `fuzz` and `tilde`.

| Features Matrix  | Directories and Files | A/AAAA DNS Entries| Vhost Enumeration | Custom Fuzzing | 8.3 Short Names 
|---|---|---|---|---| --- |
| **DirBuster** | ✓ | ✗ | ✗ | ✗ | ✗ |
| **Gobuster**  | ✓  | ✓ | ✓ | ✗ | ✗ |
| **Wfuzz**     | ✓ | ✗ | ✓ | ✓ | ✗ |
| **Patator**   | ✗ | ✗ | ✗ | ✓ | ✗ |
| **IIS Short Name Scanner** | ✗ | ✗ | ✗ | ✗ | ✓ |
| **Rustbuster** | ✓ | ✓ | ✓ | ✓ | ✓ |

## Modules

Let's see each available modules in detail.

### `dir` — _Directories and files enumeration mode_

The `dir` module can be used to discover new content. You can set up a wordlist and an extensions list to discover directories and files hosted on the web server. Rustbuster will send all the requests with the given concurrency level and report back which one are existing. In the following example we will enumerate the directories and files with the optional `php` extension and the concurrent requests will be limited to 10.

Example command:

```text
rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php -t 10
```

[![asciicast](https://asciinema.org/a/sMvjfHRo4SS88BuCdnXdwmbxh.svg)](https://asciinema.org/a/sMvjfHRo4SS88BuCdnXdwmbxh)

### `dns` — _A/AAAA DNS entries enumeration mode_

The `dns` module can be used to discover subdomains of a given domain. It works by simply asking your default DNS resolver to resolve potential hostnames and reporting which one successfully resolve. In the following example we will enumerate the subdomains of `google.com` by iterating the provided wordlist.

Example command:

```text
rustbuster dns -u google.com -w examples/wordlist
```

[![asciicast](https://asciinema.org/a/cunb8Nf8p90pMztu6kPkbINJY.svg)](https://asciinema.org/a/cunb8Nf8p90pMztu6kPkbINJY)

### `vhost` — _Virtual hosts enumeration mode_

The `vhost` module can be used to enumerate which [Virtual Hosts](https://en.wikipedia.org/wiki/Virtual_hosting) are available on the web server. It works by fuzzing the [Host HTTP Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) using the given wordlist and filtering out the results by checking the presence of provided `-x,--ignore-string` parameter in the HTTP body of the response.
In the following example we will bruteforce the available Vhosts, ignoring all the responses that contains the world `Hello` in the HTTP body.

Example command:

```text
rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x "Hello"
```

[![asciicast](https://asciinema.org/a/zxlx9aahMYyvhmZxdsKfZz3Ph.svg)](https://asciinema.org/a/zxlx9aahMYyvhmZxdsKfZz3Ph)

### `fuzz` — _Custom fuzzing enumeration mode_

The `fuzz` module can be used when a more flexible fuzzing pattern is needed. You can define the injection points and a wordlist for each of them. A [cartesian product](https://en.wikipedia.org/wiki/Cartesian_product) of requests will be generated. CSRF token are also supported! In the following example we will bruteforce a login form that requires a different CSRF token per request, that will be extracted by applying a RegEx.

Example command:

```text
rustbuster fuzz -u http://localhost:3000/login \
    -X POST \
    -H "Content-Type: application/json" \
    -b '{"user":"FUZZ","password":"FUZZ","csrf":"CSRFCSRF"}' \
    -w examples/wordlist \
    -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt \
    -s 200 \
    --csrf-url "http://localhost:3000/csrf" \
    --csrf-regex '\{"csrf":"(\w+)"\}'
```

[![asciicast](https://asciinema.org/a/yMhk9C5HcKtrlkzFJS9a8m2WR.svg)](https://asciinema.org/a/yMhk9C5HcKtrlkzFJS9a8m2WR)

### `tilde` — _IIS 8.3 shortname enumeration mode_

The `tilde` module can be used to exploit the [known information disclosure issue](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf) related to Microsoft IIS and [DOS 8.3 filenames](https://en.wikipedia.org/wiki/8.3_filename) that makes possible to easily enumerate the server side file system structure. In the following example we will enumerate available 8.3 short names by using the `.aspx` redirection extension and `OPTIONS` as HTTP method.

```text
rustbuster tilde -u http://localhost:3000/ -e aspx -X OPTIONS
```

[![asciicast](https://asciinema.org/a/Knl1CtC0Q4gkPEaPl4hpG8eFQ.svg)](https://asciinema.org/a/Knl1CtC0Q4gkPEaPl4hpG8eFQ)

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
