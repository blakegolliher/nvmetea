//! Compile bpf/*.bpf.c with clang (CO-RE) and generate libbpf-rs skeletons.
//! The objects are embedded in the binary; monitored hosts need no toolchain.

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

/// BPF objects to build.
const OBJECTS: &[&str] = &["core", "tcp_sock", "tcp_driver", "preflight"];

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let bpf_dir = manifest.join("../../bpf").canonicalize().expect("bpf/ directory");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").expect("target arch").as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => panic!("unsupported target architecture {other}"),
    };
    for name in OBJECTS {
        let src = bpf_dir.join(format!("{name}.bpf.c"));
        SkeletonBuilder::new()
            .source(&src)
            .clang_args([
                format!("-I{}", bpf_dir.display()),
                format!("-D__TARGET_ARCH_{arch}"),
                "-Wall".to_string(),
                "-Wno-unused-function".to_string(),
            ])
            .build_and_generate(out.join(format!("{name}.skel.rs")))
            .unwrap_or_else(|e| panic!("building {}: {e:#}", src.display()));
        println!("cargo:rerun-if-changed={}", src.display());
    }
    // Native copy of the histogram bucket function, linked only into tests.
    cc::Build::new().file(bpf_dir.join("hist_native.c")).include(&bpf_dir).warnings(true).compile("nvt_hist_native");
    println!("cargo:rerun-if-changed={}", bpf_dir.join("hist_native.c").display());
    for h in ["nvmetea.h", "kernel_types.h", "hist.bpf.h", "nvme_tcp.bpf.h"] {
        println!("cargo:rerun-if-changed={}", bpf_dir.join(h).display());
    }
}
