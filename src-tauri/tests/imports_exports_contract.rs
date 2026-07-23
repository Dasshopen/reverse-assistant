use reverse_assistant_lib::models::ghidra_export::GhidraExport;
use reverse_assistant_lib::services::imports_exports::list_imports;

const REAL_ELF_EXPORT_JSON: &str = include_str!("fixtures/real-fauxware-export-v2.json");

// Regression test for a real bug: on this binary, `authenticate` calls
// `read`/`strcmp`/`open` through two levels of ELF PLT/GOT thunks (a PLT
// stub whose `calls` entry points at a GOT-resolved thunk, which itself has
// no `calls` at all and only carries `thunk_target_address`). Before the
// caller index and used-by resolution became thunk-aware, every one of
// these imports reported zero users despite being genuinely called.
#[test]
fn real_elf_import_users_are_resolved_through_plt_got_thunk_chains() {
    let export = GhidraExport::parse_and_validate(REAL_ELF_EXPORT_JSON)
        .expect("a real headless ELF v2 export should be valid");

    let imports = list_imports(&export);

    let used_by_count = |name: &str| -> usize {
        imports
            .iter()
            .find(|import| import.name == name)
            .unwrap_or_else(|| panic!("{name} should be present as an import"))
            .used_by_function_count
    };

    // authenticate is the sole (real, non-thunk) caller of each.
    assert_eq!(used_by_count("strcmp"), 1);
    assert_eq!(used_by_count("open"), 1);

    // authenticate and main both call read; accepted and main both call
    // puts -- two distinct real callers reached through separate thunk
    // chains, deduplicated correctly.
    assert_eq!(used_by_count("read"), 2);
    assert_eq!(used_by_count("puts"), 2);

    // rejected is the sole caller of printf.
    assert_eq!(used_by_count("printf"), 1);
}
