use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Launch an isolated Chromium-family profile configured to use Proxelar.
pub fn launch(url: &str, proxy: SocketAddr, profile: &Path) -> io::Result<Child> {
    std::fs::create_dir_all(profile)?;
    let executable = find_browser().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Chrome, Chromium, Brave, or Edge was not found",
        )
    })?;
    Command::new(executable)
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--proxy-server=http://{proxy}"))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--new-window")
        .arg(url)
        .spawn()
}

fn find_browser() -> Option<PathBuf> {
    platform_candidates()
        .into_iter()
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .or_else(|| {
            path_candidates().into_iter().find_map(|candidate| {
                Command::new(candidate)
                    .arg("--version")
                    .output()
                    .ok()
                    .filter(|output| output.status.success())
                    .map(|_| PathBuf::from(candidate))
            })
        })
}

fn platform_candidates() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

fn path_candidates() -> Vec<&'static str> {
    #[cfg(target_os = "windows")]
    {
        vec!["chrome.exe", "msedge.exe", "brave.exe", "chromium.exe"]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "microsoft-edge",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_lists_are_non_empty_for_supported_platforms() {
        assert!(!platform_candidates().is_empty() || !path_candidates().is_empty());
    }
}
