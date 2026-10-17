//! A guest's kernel command line is measured, and what it hardens is only
//! hardened if the kernel reads each setting as its own word. Two settings
//! run together read as one value of the first, so `hpet=disableinit_on_free=1`
//! leaves freed pages unscrubbed with nothing to say so. Each line must carry
//! every setting below as a whole word.

use std::fs;
use std::path::{Path, PathBuf};

fn cmdlines() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the repository root")
        .join("image/cmdline")
}

/// What every guest boots with: a panic that stops it, trusted time with no
/// other clocksource, and no process tracing another.
const EVERY_GUEST: [&str; 7] = [
    "panic=-1",
    "oops=panic",
    "no-kvmclock",
    "tsc=reliable",
    "idle=halt",
    "hpet=disable",
    "sysctl.kernel.yama.ptrace_scope=3",
];

/// Each role, and whether it holds plaintext. Those that do scrub what they
/// free; storage holds only sealed bytes and is left out.
const ROLES: [(&str, bool); 5] = [
    ("api", true),
    ("compile-worker", true),
    ("execution-worker", true),
    ("gateway", true),
    ("storage", false),
];

#[test]
fn every_guest_reads_each_hardening_setting_as_a_word() {
    let root = cmdlines();
    for (role, holds_plaintext) in ROLES {
        for variant in ["debug", "production"] {
            let path = root.join(role).join(variant);
            let line = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            let words: Vec<&str> = line.split_whitespace().collect();
            let mut wanted: Vec<&str> = EVERY_GUEST.to_vec();
            if holds_plaintext {
                wanted.push("init_on_free=1");
            }
            for setting in wanted {
                assert!(
                    words.contains(&setting),
                    "{} does not carry `{setting}` as a word of its own",
                    path.display()
                );
            }
        }
    }
}
