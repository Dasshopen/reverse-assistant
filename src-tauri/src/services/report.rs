use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::models::ghidra_export::{DetectedTypeKind, GhidraExport};
use crate::services::imports_exports;
use crate::services::program_overview;

const PAGE_WIDTH: u32 = 595;
const PAGE_HEIGHT: u32 = 842;
const LINES_PER_PAGE: usize = 52;
const MAX_FUNCTIONS: usize = 250;
const MAX_STRINGS: usize = 150;
const MAX_TYPES: usize = 150;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfReportResult {
    pub path: String,
    pub page_count: usize,
    pub function_count_included: usize,
    pub string_count_included: usize,
    pub type_count_included: usize,
}

fn kind_label(kind: DetectedTypeKind) -> &'static str {
    match kind {
        DetectedTypeKind::Struct => "struct",
        DetectedTypeKind::Union => "union",
        DetectedTypeKind::Enum => "enum",
        DetectedTypeKind::Typedef => "typedef",
    }
}

fn push_wrapped(lines: &mut Vec<String>, text: impl AsRef<str>) {
    const WIDTH: usize = 88;
    let text = text.as_ref().trim();

    if text.is_empty() {
        lines.push(String::new());
        return;
    }

    let mut current = String::new();
    for word in text.split_whitespace() {
        let extra = usize::from(!current.is_empty());
        if !current.is_empty() && current.chars().count() + extra + word.chars().count() > WIDTH {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
}

fn report_lines(export: &GhidraExport) -> Vec<String> {
    let overview = program_overview::compute_overview(export);
    let imports = imports_exports::list_imports(export);
    let mut lines = Vec::new();

    push_wrapped(&mut lines, "REVERSE ASSISTANT - ANALYSIS REPORT");
    push_wrapped(&mut lines, "===================================");
    push_wrapped(&mut lines, format!("Program: {}", export.program.name));
    push_wrapped(&mut lines, format!("SHA-256: {}", export.program.sha256));
    push_wrapped(
        &mut lines,
        format!(
            "Format: {} | Architecture: {} | Image base: {}",
            export.program.format, export.program.architecture, export.program.image_base
        ),
    );
    lines.push(String::new());

    push_wrapped(&mut lines, "OVERVIEW");
    push_wrapped(
        &mut lines,
        format!(
            "Functions: {} ({} internal, {} external, {} thunks, {} decompiled)",
            overview.function_count,
            overview.internal_function_count,
            overview.external_function_count,
            overview.thunk_function_count,
            overview.decompiled_function_count
        ),
    );
    push_wrapped(
        &mut lines,
        format!("Call sites: {}", overview.call_site_count),
    );
    push_wrapped(
        &mut lines,
        format!(
            "Strings: {} distinct, {} references",
            overview.string_count, overview.total_string_reference_count
        ),
    );
    push_wrapped(
        &mut lines,
        format!(
            "Imports: {} | External entry points: {} | Required libraries: {}",
            imports.len(),
            overview.external_entry_point_count,
            overview.required_library_count
        ),
    );
    push_wrapped(
        &mut lines,
        format!(
            "Detected types: {} ({} structs, {} unions, {} enums, {} typedefs)",
            overview.detected_type_count,
            overview.struct_count,
            overview.union_count,
            overview.enum_count,
            overview.typedef_count
        ),
    );
    lines.push(String::new());

    push_wrapped(&mut lines, "REQUIRED LIBRARIES");
    if export.program.required_libraries.is_empty() {
        push_wrapped(&mut lines, "None identified.");
    } else {
        for library in &export.program.required_libraries {
            push_wrapped(&mut lines, format!("- {library}"));
        }
    }
    lines.push(String::new());

    push_wrapped(&mut lines, "IMPORTS");
    if imports.is_empty() {
        push_wrapped(&mut lines, "None identified.");
    } else {
        for import in &imports {
            push_wrapped(
                &mut lines,
                format!(
                    "- {} {} [{}] - used by {} functions",
                    import.entry_address,
                    import.name,
                    import.library.as_deref().unwrap_or("unknown library"),
                    import.used_by_function_count
                ),
            );
        }
    }
    lines.push(String::new());

    push_wrapped(&mut lines, "FUNCTIONS");
    for function in export.functions.iter().take(MAX_FUNCTIONS) {
        let namespace = function
            .namespace
            .as_deref()
            .map(|value| format!("{value}::"))
            .unwrap_or_default();
        let parameters = function
            .parameters
            .iter()
            .map(|parameter| format!("{} {}", parameter.data_type, parameter.name))
            .collect::<Vec<_>>()
            .join(", ");
        push_wrapped(
            &mut lines,
            format!(
                "- {} {}{}({}) -> {} | calls: {}{}{}",
                function.entry_address,
                namespace,
                function.name,
                parameters,
                function.return_type,
                function.calls.len() + usize::from(function.thunk_target_address.is_some()),
                if function.is_external {
                    " | external"
                } else {
                    ""
                },
                if function.is_thunk { " | thunk" } else { "" }
            ),
        );
    }
    if export.functions.len() > MAX_FUNCTIONS {
        push_wrapped(
            &mut lines,
            format!(
                "[{} additional functions omitted from this bounded report]",
                export.functions.len() - MAX_FUNCTIONS
            ),
        );
    }
    lines.push(String::new());

    push_wrapped(&mut lines, "STRINGS");
    for string in export.strings.iter().take(MAX_STRINGS) {
        push_wrapped(
            &mut lines,
            format!(
                "- {} [{} references] {}",
                string.address,
                string.references.len(),
                string.value
            ),
        );
    }
    if export.strings.len() > MAX_STRINGS {
        push_wrapped(
            &mut lines,
            format!(
                "[{} additional strings omitted from this bounded report]",
                export.strings.len() - MAX_STRINGS
            ),
        );
    }
    lines.push(String::new());

    push_wrapped(&mut lines, "DETECTED TYPES");
    for detected_type in export.types.iter().take(MAX_TYPES) {
        push_wrapped(
            &mut lines,
            format!(
                "- {} {} | size: {} | fields: {} | usages: {}{}{}",
                kind_label(detected_type.kind),
                detected_type.name,
                detected_type
                    .size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "unknown".to_owned()),
                detected_type.fields.len(),
                detected_type.usages.len(),
                if detected_type.is_opaque {
                    " | opaque"
                } else {
                    ""
                },
                if detected_type.is_anonymous {
                    " | anonymous"
                } else {
                    ""
                }
            ),
        );
    }
    if export.types.len() > MAX_TYPES {
        push_wrapped(
            &mut lines,
            format!(
                "[{} additional types omitted from this bounded report]",
                export.types.len() - MAX_TYPES
            ),
        );
    }

    lines
}

fn ascii_pdf_text(input: &str) -> String {
    let mut output = String::new();
    for character in input.chars() {
        let replacement = match character {
            'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' | 'À' | 'Á' | 'Â' | 'Ä' | 'Ã' | 'Å' => {
                "a"
            }
            'ç' | 'Ç' => "c",
            'è' | 'é' | 'ê' | 'ë' | 'È' | 'É' | 'Ê' | 'Ë' => "e",
            'ì' | 'í' | 'î' | 'ï' | 'Ì' | 'Í' | 'Î' | 'Ï' => "i",
            'ñ' | 'Ñ' => "n",
            'ò' | 'ó' | 'ô' | 'ö' | 'õ' | 'Ò' | 'Ó' | 'Ô' | 'Ö' | 'Õ' => "o",
            'ù' | 'ú' | 'û' | 'ü' | 'Ù' | 'Ú' | 'Û' | 'Ü' => "u",
            'ý' | 'ÿ' | 'Ý' => "y",
            'œ' | 'Œ' => "oe",
            'æ' | 'Æ' => "ae",
            '–' | '—' => "-",
            '→' => "->",
            character if character.is_ascii() && !character.is_ascii_control() => {
                output.push(character);
                continue;
            }
            _ => "?",
        };
        output.push_str(replacement);
    }
    output
}

fn escape_pdf_literal(input: &str) -> String {
    ascii_pdf_text(input)
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

pub fn build_pdf(export: &GhidraExport) -> (Vec<u8>, usize) {
    let mut lines = report_lines(export);
    if lines.is_empty() {
        lines.push("No report data available.".to_owned());
    }
    let page_count = lines.len().div_ceil(LINES_PER_PAGE);
    let mut objects: Vec<Vec<u8>> = Vec::new();

    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());

    let page_ids = (0..page_count)
        .map(|index| 4 + index * 2)
        .collect::<Vec<_>>();
    let kids = page_ids
        .iter()
        .map(|id| format!("{id} 0 R"))
        .collect::<Vec<_>>()
        .join(" ");
    objects.push(format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>").into_bytes());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec());

    for (page_index, page_lines) in lines.chunks(LINES_PER_PAGE).enumerate() {
        let content_id = 5 + page_index * 2;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );

        let mut stream = String::from("BT\n/F1 9 Tf\n42 800 Td\n");
        for (line_index, line) in page_lines.iter().enumerate() {
            if line_index > 0 {
                stream.push_str("0 -14 Td\n");
            }
            stream.push('(');
            stream.push_str(&escape_pdf_literal(line));
            stream.push_str(") Tj\n");
        }
        stream.push_str("ET\n");
        objects.push(
            format!(
                "<< /Length {} >>\nstream\n{}endstream",
                stream.len(),
                stream
            )
            .into_bytes(),
        );
    }

    let mut pdf = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        pdf.extend_from_slice(object);
        pdf.extend_from_slice(b"\nendobj\n");
    }

    let xref_offset = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );

    (pdf, page_count)
}

pub fn export_pdf(export: &GhidraExport, destination: &Path) -> Result<PdfReportResult, String> {
    if !destination
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
    {
        return Err("the report destination must use the .pdf extension".to_owned());
    }
    if let Some(parent) = destination.parent() {
        if !parent.is_dir() {
            return Err(format!(
                "the report destination directory does not exist: {}",
                parent.display()
            ));
        }
    }

    let (pdf, page_count) = build_pdf(export);
    fs::write(destination, pdf).map_err(|error| {
        format!(
            "failed to write PDF report '{}': {error}",
            destination.display()
        )
    })?;

    Ok(PdfReportResult {
        path: destination.to_string_lossy().into_owned(),
        page_count,
        function_count_included: export.functions.len().min(MAX_FUNCTIONS),
        string_count_included: export.strings.len().min(MAX_STRINGS),
        type_count_included: export.types.len().min(MAX_TYPES),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_ELF_EXPORT_JSON: &str =
        include_str!("../../tests/fixtures/real-fauxware-export-v2.json");

    #[test]
    fn real_export_produces_a_structurally_complete_pdf_with_real_evidence() {
        let export = GhidraExport::parse_and_validate(REAL_ELF_EXPORT_JSON)
            .expect("the real fixture should parse");
        let (pdf, pages) = build_pdf(&export);
        let text = String::from_utf8_lossy(&pdf);

        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        assert!(pages >= 1);
        assert!(text.contains("authenticate"));
        assert!(text.contains("SOSNEAKY"));
        assert!(text.contains("xref"));
    }

    #[test]
    fn pdf_literals_are_escaped_and_non_ascii_text_is_safely_transliterated() {
        assert_eq!(escape_pdf_literal("démo (x) \\"), "demo \\(x\\) \\\\");
    }

    #[test]
    fn export_pdf_writes_the_complete_document_to_disk() {
        let export = GhidraExport::parse_and_validate(REAL_ELF_EXPORT_JSON)
            .expect("the real fixture should parse");
        let destination = std::env::temp_dir().join(format!(
            "reverse-assistant-report-test-{}.pdf",
            std::process::id()
        ));

        let result = export_pdf(&export, &destination).expect("the PDF should be written");
        let bytes = fs::read(&destination).expect("the written PDF should be readable");
        assert_eq!(result.path, destination.to_string_lossy());
        assert!(result.page_count >= 1);
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));

        fs::remove_file(destination).expect("the test PDF should be removed");
    }
}
