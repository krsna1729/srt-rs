//! Compiles the libsrt 1.5.7 receive-side oracle when `LIBSRT_SRC` names a
//! libsrt source checkout; without it the crate builds with no native code and
//! its differential tests report that they were skipped.
//!
//! Only the receive-buffer closure of libsrt is compiled: `CRcvBuffer`,
//! `CTsbpdTime`, `CRcvLossList`, `CUnitQueue`, `CPacket` and their support
//! code. `queue.cpp` also holds the socket workers; their references to the
//! rest of libsrt are never reached from the shim and are discarded by the
//! linker's section garbage collection, which rustc always enables.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// libsrt sources the oracle needs, relative to `srtcore/`.
const LIBSRT_SOURCES: &[&str] = &[
    "buffer_rcv.cpp",
    "tsbpd_time.cpp",
    "list.cpp",
    "queue.cpp",
    "packet.cpp",
    "common.cpp",
    "strerror_defs.cpp",
    "sync.cpp",
    "sync_cxx11.cpp",
];

/// The only libsrt release this oracle is calibrated against.
const PINNED_VERSION: &str = "1.5.7";

fn main() {
    println!("cargo::rerun-if-env-changed=LIBSRT_SRC");
    println!("cargo::rerun-if-changed=cpp/receiver_shim.h");
    println!("cargo::rerun-if-changed=cpp/receiver_shim.cpp");
    println!("cargo::rustc-check-cfg=cfg(libsrt_oracle)");

    let Some(root) = env::var_os("LIBSRT_SRC").filter(|value| !value.is_empty()) else {
        return;
    };
    let root = PathBuf::from(root);
    check_version(&root);
    let generated = generate_version_header(&root);

    // Cargo must rebuild on header-only changes too: the oracle includes
    // inline clock/buffer operations and ABI definitions from these trees.
    for directory in ["srtcore", "haicrypt", "common"] {
        println!("cargo::rerun-if-changed={}", root.join(directory).display());
    }
    println!(
        "cargo::rerun-if-changed={}",
        root.join("CMakeLists.txt").display()
    );
    let srtcore = root.join("srtcore");

    // The shim links first so its references resolve against the library.
    configured(&root, &generated)
        .file("cpp/receiver_shim.cpp")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .compile("srt_libsrt_diff_shim");
    let library = configured(&root, &generated);
    library
        .clone()
        .files(LIBSRT_SOURCES.iter().map(|source| srtcore.join(source)))
        .warnings(false)
        .compile("srt_libsrt_diff_libsrt");
    link_cxx_runtime_of(&library);

    println!("cargo::rustc-cfg=libsrt_oracle");
}

/// Let the final link find the C++ runtime of the compiler that built the
/// objects. rustc links with its own driver (here possibly clang, which may
/// select a GCC installation without a matching libstdc++), so point it at
/// the directory the C++ compiler itself would use.
fn link_cxx_runtime_of(build: &cc::Build) {
    let Ok(compiler) = build.try_get_compiler() else {
        return;
    };
    let Ok(output) = compiler
        .to_command()
        .arg("-print-file-name=libstdc++.so")
        .output()
    else {
        return;
    };
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if let Some(directory) = path.is_absolute().then(|| path.parent()).flatten() {
        println!("cargo::rustc-link-search=native={}", directory.display());
    }
}

/// One configuration for the shim and libsrt: C++17, Linux, standard C++
/// synchronization (no custom-clock calibration at static initialization,
/// `sync_posix.cpp:112-137`), logging, encryption and bonding compiled out,
/// and assertions kept.
fn configured(root: &Path, generated: &Path) -> cc::Build {
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .include(root.join("srtcore"))
        .include(root.join("haicrypt"))
        .include(root.join("common"))
        .include(generated)
        .include("cpp")
        .define("LINUX", "1")
        .define("_GNU_SOURCE", None)
        .define("ENABLE_STDCXX_SYNC", "1")
        .define("HAI_ENABLE_SRT", "1")
        .define("HAI_PATCH", "1")
        .define("SRT_VERSION", "\"1.5.7\"")
        .flag_if_supported("-ffunction-sections")
        .flag_if_supported("-fdata-sections");
    build
}

fn check_version(root: &Path) {
    let cmake = root.join("CMakeLists.txt");
    let text = fs::read_to_string(&cmake)
        .unwrap_or_else(|error| panic!("LIBSRT_SRC: cannot read {}: {error}", cmake.display()));
    let expected = format!("set (SRT_VERSION {PINNED_VERSION})");
    assert!(
        text.lines().any(|line| line.trim() == expected),
        "LIBSRT_SRC={} is not libsrt {PINNED_VERSION} (no `{expected}` in CMakeLists.txt)",
        root.display()
    );
}

/// `srt.h` includes `version.h`, which CMake generates from `version.h.in`
/// (`CMakeLists.txt:1100-1103`).
fn generate_version_header(root: &Path) -> PathBuf {
    let template = root.join("srtcore").join("version.h.in");
    let text = fs::read_to_string(&template)
        .unwrap_or_else(|error| panic!("LIBSRT_SRC: cannot read {}: {error}", template.display()));
    let header = text
        .lines()
        .filter(|line| !line.starts_with("#cmakedefine"))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("@SRT_VERSION_MAJOR@", "1")
        .replace("@SRT_VERSION_MINOR@", "5")
        .replace("@SRT_VERSION_PATCH@", "7")
        .replace("@SRT_VERSION@", PINNED_VERSION);
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("libsrt");
    fs::create_dir_all(&out).expect("create OUT_DIR/libsrt");
    fs::write(out.join("version.h"), header).expect("write version.h");
    out
}
