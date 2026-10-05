//! Launch non-interactive helper tools without creating a Windows console.
//! Keep arguments, environment, captured output and exit codes unchanged.

use std::ffi::OsStr;
use std::process::Command;

pub(crate) fn background_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    configure_background_command(&mut command);
    command
}

fn configure_background_command(command: &mut Command) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW applies to console helpers, including the cmd.exe
        // wrapper Rust uses to launch Ghidra's .bat files. Do not combine it
        // with CREATE_NEW_CONSOLE or DETACHED_PROCESS, which override it.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(target_os = "windows"))]
    let _ = command;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_command_preserves_program_arguments_and_environment() {
        let mut command = background_command("helper-tool");
        command
            .arg("a path with spaces")
            .env("RA_HELPER_TEST", "value");
        assert_eq!(command.get_program(), OsStr::new("helper-tool"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [OsStr::new("a path with spaces")]
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == OsStr::new("RA_HELPER_TEST") && value == Some(OsStr::new("value"))
        }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn background_console_retains_output_and_failure_status() {
        let output = background_command("cmd.exe")
            .args([
                "/D",
                "/C",
                "echo background-output & echo background-error 1>&2 & exit /b 7",
            ])
            .output()
            .expect("Windows command interpreter should run");
        assert_eq!(output.status.code(), Some(7));
        assert!(String::from_utf8_lossy(&output.stdout).contains("background-output"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("background-error"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn background_child_has_no_console() {
        if std::env::var_os("RA_BACKGROUND_CONSOLE_PROBE").is_none() {
            return;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetConsoleWindow() -> *mut std::ffi::c_void;
        }
        // SAFETY: GetConsoleWindow has no arguments and only queries the
        // calling process's console handle; it does not change system state.
        assert!(unsafe { GetConsoleWindow() }.is_null());
        println!("background-console-probe-passed");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn background_process_runs_without_a_console_window() {
        let output = background_command(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "services::background_process::tests::background_child_has_no_console",
                "--nocapture",
            ])
            .env("RA_BACKGROUND_CONSOLE_PROBE", "1")
            .output()
            .expect("console probe should launch");
        assert!(output.status.success(), "console probe failed: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("background-console-probe-passed"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn background_console_child_remains_without_a_console_window() {
        let output = background_command("cmd.exe")
            .args(["/D", "/C"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "services::background_process::tests::background_child_has_no_console",
                "--nocapture",
            ])
            .env("RA_BACKGROUND_CONSOLE_PROBE", "1")
            .output()
            .expect("console-wrapper probe should launch");
        assert!(
            output.status.success(),
            "wrapped console probe failed: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("background-console-probe-passed"));
    }
}
