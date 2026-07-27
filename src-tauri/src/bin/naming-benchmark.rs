use std::{env, fs, process};

use reverse_assistant_lib::services::naming_benchmark::{evaluate_suite, NamingBenchmarkSuite};

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: naming-benchmark <suite.json>");
        process::exit(2);
    };
    let result = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read benchmark suite '{path}': {error}"))
        .and_then(|json| {
            serde_json::from_str::<NamingBenchmarkSuite>(&json)
                .map_err(|error| format!("invalid benchmark suite JSON: {error}"))
        })
        .and_then(|suite| evaluate_suite(&suite))
        .and_then(|report| {
            serde_json::to_string_pretty(&report)
                .map_err(|error| format!("failed to serialize benchmark report: {error}"))
        });
    match result {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}
