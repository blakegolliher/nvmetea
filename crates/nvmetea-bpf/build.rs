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
    let (arch, multiarch) = match env::var("CARGO_CFG_TARGET_ARCH").expect("target arch").as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        other => panic!("unsupported target architecture {other}"),
    };
    let mut args = vec![
        format!("-I{}", bpf_dir.display()),
        format!("-D__TARGET_ARCH_{arch}"),
        // ISA v3: the programs use atomic fetch-and-add results (kernel 5.12+;
        // every supported kernel has it). clang < 20 defaults to v1, which
        // rejects them, so pin it and get the same objects from every clang.
        "-mcpu=v3".to_string(),
        "-Wall".to_string(),
        "-Wno-unused-function".to_string(),
    ];
    // <linux/types.h> includes <asm/types.h>. Fedora/RHEL install it in
    // /usr/include/asm; Debian/Ubuntu in the multiarch directory, which
    // `clang -target bpf` does not search. Searched last, after the system dirs.
    let asm_dir = PathBuf::from("/usr/include").join(multiarch);
    if asm_dir.join("asm/types.h").exists() {
        args.push("-idirafter".to_string());
        args.push(asm_dir.display().to_string());
    }
    for name in OBJECTS {
        let src = bpf_dir.join(format!("{name}.bpf.c"));
        SkeletonBuilder::new()
            .source(&src)
            .clang_args(&args)
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
