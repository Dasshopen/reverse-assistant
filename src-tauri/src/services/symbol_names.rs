//! Presentation only: demangling never corroborates a match or changes its score.
use std::collections::HashSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_BATCH: usize = 256;
const MAX_SYMBOL_BYTES: usize = 2048;
const MAX_DECODED_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymbolPresentation {
    pub raw_name: String,
    pub display_name: String,
    pub signature: Option<String>,
    pub rename_name: Option<String>,
    pub scheme: Option<&'static str>,
    pub decoded: bool,
}

fn decode(name: &str) -> Option<(String, String, &'static str)> {
    if name.starts_with('?') {
        let signature =
            msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()).ok()?;
        let display =
            msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::NAME_ONLY).ok()?;
        Some((display, signature, "msvc"))
    } else if name.starts_with("_Z") || name.starts_with("__Z") {
        // Darwin adds an extra leading underscore to Itanium C++ symbols.
        let input = if name.starts_with("__Z") {
            &name[1..]
        } else {
            name
        };
        let symbol = cpp_demangle::Symbol::new_with_options(
            input,
            &cpp_demangle::ParseOptions::default().recursion_limit(64),
        )
        .ok()?;
        let signature = symbol
            .demangle_with_options(&cpp_demangle::DemangleOptions::default().recursion_limit(64))
            .ok()?;
        let display = symbol
            .demangle_with_options(
                &cpp_demangle::DemangleOptions::default()
                    .no_params()
                    .no_return_type()
                    .recursion_limit(64),
            )
            .ok()?;
        Some((display, signature, "itanium"))
    } else {
        None
    }
}

fn readable_name(name: &str) -> String {
    // Compiler-generated helper labels are names, not inferred behavior.
    name.replace("`scalar deleting destructor'", "scalar_deleting_destructor")
        .replace("`vector deleting destructor'", "vector_deleting_destructor")
}

fn flat_rename_name(display: &str, raw: &str) -> Option<String> {
    let mut readable = display.to_owned();
    // Preserve operator/destructor identity rather than deleting punctuation
    // (which otherwise conflates constructors/destructors or + and -).
    for (operator, label) in [
        ("new[]", "new_array"),
        ("delete[]", "delete_array"),
        ("<<=", "shift_left_assign"),
        (">>=", "shift_right_assign"),
        ("<=>", "three_way_compare"),
        ("->*", "member_access"),
        ("()", "call"),
        ("[]", "index"),
        ("++", "increment"),
        ("--", "decrement"),
        ("==", "equal"),
        ("!=", "not_equal"),
        ("<=", "less_equal"),
        (">=", "greater_equal"),
        ("<<", "shift_left"),
        (">>", "shift_right"),
        ("&&", "logical_and"),
        ("||", "logical_or"),
        ("+=", "plus_assign"),
        ("-=", "minus_assign"),
        ("*=", "multiply_assign"),
        ("/=", "divide_assign"),
        ("%=", "modulo_assign"),
        ("&=", "and_assign"),
        ("|=", "or_assign"),
        ("^=", "xor_assign"),
        ("->", "arrow"),
        ("new", "new"),
        ("delete", "delete"),
        ("+", "plus"),
        ("-", "minus"),
        ("*", "multiply"),
        ("/", "divide"),
        ("%", "modulo"),
        ("<", "less"),
        (">", "greater"),
        ("=", "assign"),
        ("!", "not"),
        ("~", "bitwise_not"),
        ("&", "and"),
        ("|", "or"),
        ("^", "xor"),
        (",", "comma"),
    ] {
        readable = readable.replace(&format!("operator{operator}"), &format!("operator_{label}"));
        readable = readable.replace(
            &format!("operator {operator}"),
            &format!("operator_{label}"),
        );
    }
    readable = readable
        .replace('~', "destructor_")
        .replace("&&", "_rref_")
        .replace('&', "_ref_")
        .replace('*', "_ptr_");
    let mut safe = String::new();
    for character in readable.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            safe.push(character);
        } else if !safe.ends_with('_') {
            safe.push('_');
        }
    }
    let mut safe = safe.trim_matches('_').to_owned();
    if safe.is_empty() {
        return None;
    }
    if safe.starts_with(|character: char| character.is_ascii_digit()) {
        safe.insert_str(0, "function_");
    }
    if safe.len() > 200 {
        let digest = Sha256::digest(raw.as_bytes());
        let suffix: String = digest[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        safe.truncate(180);
        safe.push('_');
        safe.push_str(&suffix);
    }
    Some(safe)
}

pub fn present_symbol(name: &str) -> SymbolPresentation {
    let mut result = SymbolPresentation {
        raw_name: name.to_owned(),
        display_name: name.to_owned(),
        signature: None,
        rename_name: None,
        scheme: None,
        decoded: false,
    };
    if name.len() > MAX_SYMBOL_BYTES {
        return result;
    }
    if let Some((display, signature, scheme)) = decode(name) {
        if display.is_empty()
            || display.len() > MAX_DECODED_BYTES
            || signature.len() > MAX_DECODED_BYTES
        {
            return result;
        }
        result.display_name = readable_name(&display);
        result.rename_name = flat_rename_name(&result.display_name, name);
        result.signature = Some(signature);
        result.scheme = Some(scheme);
        result.decoded = true;
    }
    result
}

pub fn present_symbols(names: &[String]) -> Result<Vec<SymbolPresentation>, String> {
    if names.len() > MAX_BATCH {
        return Err("Symbol presentation batch is too large.".to_owned());
    }
    if names.iter().any(|name| name.len() > MAX_SYMBOL_BYTES) {
        return Err("Symbol presentation input exceeds the size limit.".to_owned());
    }
    let mut seen = HashSet::new();
    Ok(names
        .iter()
        .filter(|name| seen.insert(name.as_str()))
        .map(|name| present_symbol(name))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_reported_msvc_symbol_without_inferring_match_validity() {
        let raw = "??_GCVideoCaptureTerminal@@UEAAPEAXI@Z";
        let result = present_symbol(raw);
        assert!(result.decoded);
        assert_eq!(result.raw_name, raw);
        assert_eq!(
            result.display_name,
            "CVideoCaptureTerminal::scalar_deleting_destructor"
        );
        assert_eq!(
            result.rename_name.as_deref(),
            Some("CVideoCaptureTerminal_scalar_deleting_destructor")
        );
        assert!(result.signature.unwrap().contains("unsigned int"));
    }

    #[test]
    fn constructor_destructor_and_members_have_distinct_readable_names() {
        let constructor = present_symbol("??0Widget@@QEAA@XZ");
        let destructor = present_symbol("??1Widget@@UEAA@XZ");
        let member = present_symbol("?run@Widget@@QEAAHH@Z");
        assert_eq!(constructor.display_name, "Widget::Widget");
        assert_eq!(destructor.display_name, "Widget::~Widget");
        assert_ne!(constructor.rename_name, destructor.rename_name);
        assert_eq!(member.display_name, "Widget::run");
        let scoped_member = present_symbol("?run@Widget@ns@@QEAAHH@Z");
        assert_eq!(scoped_member.display_name, "ns::Widget::run");
        let template = present_symbol("??$foo@H@@YAXH@Z");
        assert_eq!(template.display_name, "foo<int>");
        assert!(template.signature.unwrap().contains("int"));
    }

    #[test]
    fn decodes_itanium_names_templates_and_overloads_without_merging_raw_symbols() {
        let result = present_symbol("_ZN3Foo3barEi");
        assert_eq!(result.display_name, "Foo::bar");
        assert_eq!(result.signature.as_deref(), Some("Foo::bar(int)"));
        let other = present_symbol("_ZN3Foo3barEd");
        assert_ne!(result.signature, other.signature);
        assert_ne!(result.raw_name, other.raw_name);
        let template = present_symbol("_Z3fooIiEvT_");
        assert!(template.display_name.contains("foo<int>"));
        assert_eq!(
            present_symbol("__ZN3Foo3barEi").display_name,
            result.display_name
        );
    }

    #[test]
    fn preserves_operator_identity_and_bounds_flat_names() {
        assert_ne!(
            flat_rename_name("Foo::operator+", "a"),
            flat_rename_name("Foo::operator-", "b")
        );
        assert_eq!(
            flat_rename_name("Foo::operator[]", "a").as_deref(),
            Some("Foo_operator_index")
        );
        let result = flat_rename_name(&"LongTemplate".repeat(30), "raw").unwrap();
        assert!(result.len() <= 200);
        assert!(result
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    #[test]
    fn invalid_and_plain_names_remain_lossless_without_guessed_renames() {
        for raw in [
            "memcpy",
            "std::vector<int>::clear",
            "?broken",
            "_Zbroken",
            "",
        ] {
            let result = present_symbol(raw);
            assert_eq!(result.display_name, raw);
            assert_eq!(result.raw_name, raw);
            assert!(!result.decoded);
            assert!(result.rename_name.is_none());
        }
    }

    #[test]
    fn batches_deduplicate_and_enforce_limits() {
        let raw = "_ZN3Foo3barEi".to_owned();
        assert_eq!(present_symbols(&[raw.clone(), raw]).unwrap().len(), 1);
        assert!(present_symbols(&vec!["memcpy".to_owned(); MAX_BATCH + 1]).is_err());
        assert!(present_symbols(&["?".repeat(MAX_SYMBOL_BYTES + 1)]).is_err());
    }
}
