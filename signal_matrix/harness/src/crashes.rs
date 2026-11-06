//! Crashes the harness can trigger; the runner includes this file to list them.

use std::hint::black_box;

/// Names the crash that the harness triggers on non-empty inputs.
pub const ENV: &str = "SIGNAL_MATRIX_CRASH";

pub struct Crash {
    pub name: &'static str,
    pub description: &'static str,
    pub supported: bool,
    pub trigger: fn(),
}

const X86: bool = cfg!(any(target_arch = "x86", target_arch = "x86_64"));
const AARCH64: bool = cfg!(target_arch = "aarch64");

pub const CRASHES: &[Crash] = &[
    Crash {
        name: "panic",
        description: "panic!, aborted by libfuzzer-sys' panic hook",
        supported: true,
        trigger: panic,
    },
    Crash {
        name: "abort",
        description: "std::process::abort()",
        supported: true,
        trigger: abort,
    },
    Crash {
        name: "segv",
        description: "write to address 8",
        supported: true,
        trigger: segv,
    },
    Crash {
        name: "bus",
        description: "read from a mapping past the end of a file",
        supported: cfg!(unix),
        trigger: bus,
    },
    Crash {
        name: "ill",
        description: "illegal instruction (ud2 / udf)",
        supported: X86 || AARCH64,
        trigger: ill,
    },
    Crash {
        name: "fpe",
        description: if X86 {
            "integer division by zero"
        } else {
            "raise(SIGFPE), no integer division trap on this arch"
        },
        supported: X86 || cfg!(unix),
        trigger: fpe,
    },
    Crash {
        name: "trap",
        description: "breakpoint instruction (int3 / brk)",
        supported: X86 || AARCH64,
        trigger: trap,
    },
    Crash {
        name: "stack-overflow",
        description: "unbounded recursion on the main thread",
        supported: true,
        trigger: stack_overflow,
    },
    Crash {
        name: "timeout",
        description: "endless loop, caught by -timeout",
        supported: true,
        trigger: timeout,
    },
    Crash {
        name: "sigpipe",
        description: "unwrapped write to a closed pipe",
        supported: cfg!(unix),
        trigger: sigpipe,
    },
];

fn panic() {
    panic!("signal-matrix");
}

fn abort() {
    std::process::abort();
}

fn segv() {
    // non-null, so debug assertions don't report it as UB first
    unsafe { std::ptr::write_volatile(black_box(8 as *mut u8), 1) };
}

fn bus() {
    #[cfg(unix)]
    {
        use std::{fs::File, os::fd::AsRawFd, ptr};

        let path = std::env::temp_dir().join(format!("signal-matrix-{}", std::process::id()));
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        // mapping an empty file works, accessing it raises SIGBUS
        unsafe {
            let page = libc::mmap(
                ptr::null_mut(),
                1,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            );
            assert_ne!(page, libc::MAP_FAILED);
            black_box(ptr::read_volatile(page.cast::<u8>()));
        }
    }
}

fn ill() {
    unsafe {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        std::arch::asm!("ud2");
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("udf #0");
    }
}

fn fpe() {
    // Rust's `/` panics on a zero divisor instead
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        std::arch::asm!(
            "div {0:e}",
            in(reg) 0u32,
            inout("eax") 1u32 => _,
            inout("edx") 0u32 => _,
        );
    }
    #[cfg(all(unix, not(any(target_arch = "x86", target_arch = "x86_64"))))]
    unsafe {
        libc::raise(libc::SIGFPE);
    }
}

fn trap() {
    unsafe {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        std::arch::asm!("int3");
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("brk #0");
    }
}

fn stack_overflow() {
    #[allow(unconditional_recursion)]
    fn recurse(depth: u64) -> u64 {
        let frame = black_box([depth; 16]);
        recurse(depth + 1).wrapping_add(frame[0])
    }
    black_box(recurse(0));
}

fn timeout() {
    loop {
        std::hint::spin_loop();
    }
}

fn sigpipe() {
    #[cfg(unix)]
    {
        use std::{fs::File, io::Write, os::fd::FromRawFd};

        let mut fds = [0; 2];
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            libc::close(fds[0]);
        }
        let mut pipe = unsafe { File::from_raw_fd(fds[1]) };
        // EPIPE while SIGPIPE is ignored, as in a Rust `main`; otherwise SIGPIPE kills
        pipe.write_all(b"x").expect("write to a closed pipe");
    }
}
