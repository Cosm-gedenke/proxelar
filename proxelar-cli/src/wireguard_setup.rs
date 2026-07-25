use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use qrcode::{
    types::{Color, EcLevel},
    QrCode,
};

const QUIET_ZONE: usize = 4;

#[derive(Clone)]
pub(crate) struct WireGuardSetup {
    profile_name: String,
    config_path: PathBuf,
    terminal_lines: Vec<String>,
    svg: String,
}

impl WireGuardSetup {
    pub(crate) fn from_config(config_path: &Path) -> io::Result<Self> {
        let config = std::fs::read(config_path)?;
        let profile_name = config_path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid profile name"))?
            .to_owned();
        Self::from_bytes(profile_name, config_path.to_owned(), &config)
    }

    pub(crate) fn from_bytes(
        profile_name: String,
        config_path: PathBuf,
        config: &[u8],
    ) -> io::Result<Self> {
        // Low error correction keeps a full WireGuard profile in fewer modules.
        // Larger modules are considerably easier to scan from terminal fonts,
        // where antialiasing and non-square cells already reduce the margin.
        let code = QrCode::with_error_correction_level(config, EcLevel::L).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("could not encode WireGuard profile as QR: {error}"),
            )
        })?;
        let width = code.width();
        let modules = code
            .to_colors()
            .into_iter()
            .map(|color| color == Color::Dark)
            .collect::<Vec<_>>();

        Ok(Self {
            profile_name,
            config_path,
            terminal_lines: render_terminal(&modules, width),
            svg: render_svg(&modules, width),
        })
    }

    pub(crate) fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn terminal_lines(&self) -> &[String] {
        &self.terminal_lines
    }

    pub(crate) fn svg(&self) -> &str {
        &self.svg
    }
}

fn render_terminal(modules: &[bool], width: usize) -> Vec<String> {
    let size = width + QUIET_ZONE * 2;
    (0..size)
        .step_by(2)
        .map(|top_y| {
            (0..size)
                .map(|x| {
                    let top = module_at(modules, width, x, top_y);
                    let bottom = module_at(modules, width, x, top_y + 1);
                    match (top, bottom) {
                        (false, false) => ' ',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (true, true) => '█',
                    }
                })
                .collect()
        })
        .collect()
}

fn render_svg(modules: &[bool], width: usize) -> String {
    let size = width + QUIET_ZONE * 2;
    let mut path = String::new();
    for y in 0..width {
        for x in 0..width {
            if modules[y * width + x] {
                let _ = write!(path, "M{} {}h1v1h-1z", x + QUIET_ZONE, y + QUIET_ZONE);
            }
        }
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
    )
}

fn module_at(modules: &[bool], width: usize, x: usize, y: usize) -> bool {
    let Some(x) = x.checked_sub(QUIET_ZONE) else {
        return false;
    };
    let Some(y) = y.checked_sub(QUIET_ZONE) else {
        return false;
    };
    x < width && y < width && modules[y * width + x]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &[u8] = b"[Interface]\nPrivateKey = test\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = peer\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn renders_terminal_and_svg_qr_codes() {
        let setup = WireGuardSetup::from_bytes(
            "proxelar-wg".to_owned(),
            PathBuf::from("/tmp/proxelar-wg.conf"),
            SAMPLE_CONFIG,
        )
        .unwrap();

        assert_eq!(setup.profile_name(), "proxelar-wg");
        assert!(!setup.terminal_lines().is_empty());
        assert!(setup.terminal_lines().iter().any(|line| line.contains('█')));
        assert!(setup.svg().starts_with("<svg"));
        assert!(setup.svg().contains("<path"));
    }
}
