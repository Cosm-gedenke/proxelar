//! Validated, portable Lua addon packages and local catalog management.

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// File name of the versioned addon manifest.
pub const ADDON_MANIFEST_FILE: &str = "proxelar-addon.json";
/// Current addon manifest schema version.
pub const ADDON_SCHEMA_VERSION: u32 = 1;

/// A hook an addon declares that it implements.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddonHook {
    Request,
    Response,
    WebsocketFrame,
}

/// Supply-chain and discovery metadata for a portable Lua addon.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddonManifest {
    pub schema_version: u32,
    pub name: String,
    pub version: Version,
    pub description: String,
    pub entrypoint: PathBuf,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub hooks: BTreeSet<AddonHook>,
    #[serde(default)]
    pub requires_native_modules: bool,
    /// Lowercase hexadecimal SHA-256 digest for every package file except the
    /// manifest itself. Undeclared files are rejected.
    pub files: BTreeMap<PathBuf, String>,
}

/// A package that passed manifest, path, and content-integrity validation.
#[derive(Clone, Debug)]
pub struct AddonPackage {
    root: PathBuf,
    entrypoint: PathBuf,
    manifest: AddonManifest,
}

impl AddonPackage {
    /// Validate an addon package directory and all declared file digests.
    pub fn load(root: impl AsRef<Path>) -> Result<Self, AddonError> {
        let requested_root = root.as_ref();
        let root = requested_root
            .canonicalize()
            .map_err(|source| AddonError::Io {
                path: requested_root.to_owned(),
                source,
            })?;
        if !root.is_dir() {
            return Err(AddonError::NotDirectory(root));
        }

        let manifest_path = root.join(ADDON_MANIFEST_FILE);
        let bytes = fs::read(&manifest_path).map_err(|source| AddonError::Io {
            path: manifest_path.clone(),
            source,
        })?;
        let manifest: AddonManifest =
            serde_json::from_slice(&bytes).map_err(|source| AddonError::Manifest {
                path: manifest_path,
                source,
            })?;
        validate_manifest(&manifest)?;

        let files = collect_package_files(&root)?;
        let declared: BTreeSet<PathBuf> = manifest.files.keys().cloned().collect();
        let actual: BTreeSet<PathBuf> = files.iter().cloned().collect();
        if declared != actual {
            let undeclared = actual.difference(&declared).next().cloned();
            let missing = declared.difference(&actual).next().cloned();
            return Err(AddonError::FileSetMismatch {
                undeclared,
                missing,
            });
        }

        for (relative, expected) in &manifest.files {
            let path = root.join(relative);
            let actual = sha256_file(&path)?;
            if actual != *expected {
                return Err(AddonError::Integrity {
                    path: relative.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        let entrypoint = root.join(&manifest.entrypoint);
        Ok(Self {
            root,
            entrypoint,
            manifest,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn entrypoint(&self) -> &Path {
        &self.entrypoint
    }

    pub fn manifest(&self) -> &AddonManifest {
        &self.manifest
    }
}

/// Discover and validate every installed addon in a catalog directory.
pub fn discover_addons(catalog: impl AsRef<Path>) -> Result<Vec<AddonPackage>, AddonError> {
    let catalog = catalog.as_ref();
    if !catalog.exists() {
        return Ok(Vec::new());
    }
    if !catalog.is_dir() {
        return Err(AddonError::NotDirectory(catalog.to_owned()));
    }

    let mut packages = Vec::new();
    for entry in fs::read_dir(catalog).map_err(|source| AddonError::Io {
        path: catalog.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| AddonError::Io {
            path: catalog.to_owned(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| AddonError::Io {
            path: entry.path(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(AddonError::Symlink(entry.path()));
        }
        if file_type.is_dir() && entry.path().join(ADDON_MANIFEST_FILE).is_file() {
            packages.push(AddonPackage::load(entry.path())?);
        }
    }
    packages.sort_by(|left, right| left.manifest.name.cmp(&right.manifest.name));
    Ok(packages)
}

/// Resolve an installed addon by its validated manifest name.
pub fn find_addon(catalog: impl AsRef<Path>, name: &str) -> Result<AddonPackage, AddonError> {
    validate_name(name)?;
    let package = AddonPackage::load(catalog.as_ref().join(name))?;
    if package.manifest.name != name {
        return Err(AddonError::CatalogNameMismatch {
            requested: name.to_owned(),
            manifest: package.manifest.name.clone(),
        });
    }
    Ok(package)
}

/// Atomically install a validated local addon into a catalog.
///
/// Existing addon directories are never overwritten. The source package is
/// fully verified before any destination is created.
pub fn install_addon(
    source: impl AsRef<Path>,
    catalog: impl AsRef<Path>,
) -> Result<AddonPackage, AddonError> {
    let source = AddonPackage::load(source)?;
    let catalog = catalog.as_ref();
    create_private_directory(catalog)?;
    let destination = catalog.join(&source.manifest.name);
    if destination.exists() {
        return Err(AddonError::AlreadyInstalled(destination));
    }

    let temporary = catalog.join(format!(
        ".{}.{}.installing-{}",
        source.manifest.name,
        source.manifest.version,
        std::process::id()
    ));
    if temporary.exists() {
        return Err(AddonError::TemporaryPathExists(temporary));
    }
    create_private_directory(&temporary)?;

    let copy_result = (|| {
        copy_regular_file(
            &source.root.join(ADDON_MANIFEST_FILE),
            &temporary.join(ADDON_MANIFEST_FILE),
        )?;
        for relative in source.manifest.files.keys() {
            let target = temporary.join(relative);
            if let Some(parent) = target.parent() {
                create_private_directory(parent)?;
            }
            copy_regular_file(&source.root.join(relative), &target)?;
        }
        fs::rename(&temporary, &destination).map_err(|source| AddonError::Io {
            path: destination.clone(),
            source,
        })?;
        Ok::<(), AddonError>(())
    })();

    if copy_result.is_err() && temporary.exists() {
        let _ = fs::remove_dir_all(&temporary);
    }
    copy_result?;
    AddonPackage::load(destination)
}

fn validate_manifest(manifest: &AddonManifest) -> Result<(), AddonError> {
    if manifest.schema_version != ADDON_SCHEMA_VERSION {
        return Err(AddonError::UnsupportedSchema(manifest.schema_version));
    }
    validate_name(&manifest.name)?;
    if manifest.description.trim().is_empty() {
        return Err(AddonError::EmptyDescription);
    }
    validate_relative_path(&manifest.entrypoint)?;
    if !manifest.files.contains_key(&manifest.entrypoint) {
        return Err(AddonError::EntrypointNotDeclared(
            manifest.entrypoint.clone(),
        ));
    }
    for (path, digest) in &manifest.files {
        validate_relative_path(path)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AddonError::InvalidDigest {
                path: path.clone(),
                digest: digest.clone(),
            });
        }
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), AddonError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.ends_with('-');
    if valid {
        Ok(())
    } else {
        Err(AddonError::InvalidName(name.to_owned()))
    }
}

fn validate_relative_path(path: &Path) -> Result<(), AddonError> {
    let valid = !path.as_os_str().is_empty()
        && path.components().all(|component| {
            matches!(component, Component::Normal(_))
                && component.as_os_str() != ADDON_MANIFEST_FILE
        });
    if valid {
        Ok(())
    } else {
        Err(AddonError::InvalidPath(path.to_owned()))
    }
}

fn collect_package_files(root: &Path) -> Result<Vec<PathBuf>, AddonError> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), AddonError> {
        for entry in fs::read_dir(directory).map_err(|source| AddonError::Io {
            path: directory.to_owned(),
            source,
        })? {
            let entry = entry.map_err(|source| AddonError::Io {
                path: directory.to_owned(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| AddonError::Io {
                path: path.clone(),
                source,
            })?;
            if file_type.is_symlink() {
                return Err(AddonError::Symlink(path));
            }
            if file_type.is_dir() {
                visit(root, &path, files)?;
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .expect("walked file stays inside addon root")
                    .to_owned();
                if relative != Path::new(ADDON_MANIFEST_FILE) {
                    files.push(relative);
                }
            } else {
                return Err(AddonError::SpecialFile(path));
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn sha256_file(path: &Path) -> Result<String, AddonError> {
    let bytes = fs::read(path).map_err(|source| AddonError::Io {
        path: path.to_owned(),
        source,
    })?;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn create_private_directory(path: &Path) -> Result<(), AddonError> {
    fs::create_dir_all(path).map_err(|source| AddonError::Io {
        path: path.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            AddonError::Io {
                path: path.to_owned(),
                source,
            }
        })?;
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), AddonError> {
    fs::copy(source, destination).map_err(|source| AddonError::Io {
        path: destination.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).map_err(|source| {
            AddonError::Io {
                path: destination.to_owned(),
                source,
            }
        })?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum AddonError {
    #[error("addon I/O error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("invalid addon manifest at {path}: {source}")]
    Manifest {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("addon path is not a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("unsupported addon schema version {0}")]
    UnsupportedSchema(u32),
    #[error("addon name must be a lowercase slug of at most 64 characters: {0:?}")]
    InvalidName(String),
    #[error("addon description must not be empty")]
    EmptyDescription,
    #[error("addon path must be relative, normalized, and cannot name the manifest: {0}")]
    InvalidPath(PathBuf),
    #[error("addon entrypoint is not declared in files: {0}")]
    EntrypointNotDeclared(PathBuf),
    #[error("invalid lowercase SHA-256 digest for {path}: {digest:?}")]
    InvalidDigest { path: PathBuf, digest: String },
    #[error(
        "addon file set does not match manifest (undeclared: {undeclared:?}, missing: {missing:?})"
    )]
    FileSetMismatch {
        undeclared: Option<PathBuf>,
        missing: Option<PathBuf>,
    },
    #[error("addon integrity check failed for {path}: expected {expected}, got {actual}")]
    Integrity {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("addon packages cannot contain symbolic links: {0}")]
    Symlink(PathBuf),
    #[error("addon packages cannot contain special files: {0}")]
    SpecialFile(PathBuf),
    #[error("installed addon name {manifest:?} does not match requested name {requested:?}")]
    CatalogNameMismatch { requested: String, manifest: String },
    #[error("addon is already installed at {0}")]
    AlreadyInstalled(PathBuf),
    #[error("stale addon installation path exists: {0}")]
    TemporaryPathExists(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn package(root: &Path, name: &str, script: &[u8]) {
        fs::write(root.join("init.lua"), script).unwrap();
        let digest = sha256_file(&root.join("init.lua")).unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": name,
            "version": "1.2.3",
            "description": "test addon",
            "entrypoint": "init.lua",
            "hooks": ["request"],
            "files": { "init.lua": digest }
        });
        fs::write(
            root.join(ADDON_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn validates_and_installs_package() {
        let source = tempdir().unwrap();
        package(source.path(), "header-tagger", b"return nil\n");
        let catalog = tempdir().unwrap();

        let installed = install_addon(source.path(), catalog.path()).unwrap();
        assert_eq!(installed.manifest().name, "header-tagger");
        assert_eq!(discover_addons(catalog.path()).unwrap().len(), 1);
        assert_eq!(
            find_addon(catalog.path(), "header-tagger")
                .unwrap()
                .manifest()
                .version,
            Version::new(1, 2, 3)
        );
    }

    #[test]
    fn rejects_tampering_and_undeclared_files() {
        let source = tempdir().unwrap();
        package(source.path(), "header-tagger", b"return nil\n");
        fs::write(source.path().join("init.lua"), "tampered").unwrap();
        assert!(matches!(
            AddonPackage::load(source.path()),
            Err(AddonError::Integrity { .. })
        ));

        package(source.path(), "header-tagger", b"return nil\n");
        fs::write(source.path().join("undeclared.lua"), "return nil").unwrap();
        assert!(matches!(
            AddonPackage::load(source.path()),
            Err(AddonError::FileSetMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let source = tempdir().unwrap();
        package(source.path(), "header-tagger", b"return nil\n");
        symlink(
            source.path().join("init.lua"),
            source.path().join("link.lua"),
        )
        .unwrap();
        assert!(matches!(
            AddonPackage::load(source.path()),
            Err(AddonError::Symlink(_))
        ));
    }

    #[test]
    fn validates_manifest_names_paths_and_digests() {
        for valid in ["a", "header-tagger", "addon2"] {
            validate_name(valid).unwrap();
        }
        for invalid in [
            "",
            "Uppercase",
            "-leading",
            "trailing-",
            "under_score",
            &"a".repeat(65),
        ] {
            assert!(matches!(
                validate_name(invalid),
                Err(AddonError::InvalidName(_))
            ));
        }

        validate_relative_path(Path::new("lib/helper.lua")).unwrap();
        for invalid in ["", "../init.lua", "/init.lua", ADDON_MANIFEST_FILE] {
            assert!(matches!(
                validate_relative_path(Path::new(invalid)),
                Err(AddonError::InvalidPath(_))
            ));
        }

        let mut manifest = AddonManifest {
            schema_version: ADDON_SCHEMA_VERSION,
            name: "test-addon".to_owned(),
            version: Version::new(1, 0, 0),
            description: "test".to_owned(),
            entrypoint: "init.lua".into(),
            authors: Vec::new(),
            license: None,
            homepage: None,
            hooks: BTreeSet::new(),
            requires_native_modules: false,
            files: BTreeMap::from([("init.lua".into(), "a".repeat(64))]),
        };
        validate_manifest(&manifest).unwrap();

        manifest.schema_version += 1;
        assert!(matches!(
            validate_manifest(&manifest),
            Err(AddonError::UnsupportedSchema(_))
        ));
        manifest.schema_version = ADDON_SCHEMA_VERSION;
        manifest.description = " ".to_owned();
        assert!(matches!(
            validate_manifest(&manifest),
            Err(AddonError::EmptyDescription)
        ));
        manifest.description = "test".to_owned();
        manifest.entrypoint = "missing.lua".into();
        assert!(matches!(
            validate_manifest(&manifest),
            Err(AddonError::EntrypointNotDeclared(_))
        ));
        manifest.entrypoint = "init.lua".into();
        manifest.files.insert("init.lua".into(), "ABC".to_owned());
        assert!(matches!(
            validate_manifest(&manifest),
            Err(AddonError::InvalidDigest { .. })
        ));
    }

    #[test]
    fn discovers_catalog_edges_and_refuses_overwrites() {
        let root = tempdir().unwrap();
        assert!(discover_addons(root.path().join("missing"))
            .unwrap()
            .is_empty());

        let catalog_file = root.path().join("catalog-file");
        fs::write(&catalog_file, "not a directory").unwrap();
        assert!(matches!(
            discover_addons(&catalog_file),
            Err(AddonError::NotDirectory(_))
        ));

        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        package(&source, "header-tagger", b"return nil\n");
        let loaded = AddonPackage::load(&source).unwrap();
        assert_eq!(loaded.root(), source.canonicalize().unwrap());
        assert_eq!(loaded.entrypoint(), loaded.root().join("init.lua"));

        let catalog = root.path().join("catalog");
        let first = install_addon(&source, &catalog).unwrap();
        assert_eq!(first.manifest().name, "header-tagger");
        assert!(matches!(
            install_addon(&source, &catalog),
            Err(AddonError::AlreadyInstalled(_))
        ));

        let mismatched = catalog.join("wrong-name");
        fs::create_dir(&mismatched).unwrap();
        package(&mismatched, "actual-name", b"return nil\n");
        assert!(matches!(
            find_addon(&catalog, "wrong-name"),
            Err(AddonError::CatalogNameMismatch { .. })
        ));
        assert!(matches!(
            find_addon(&catalog, "../escape"),
            Err(AddonError::InvalidName(_))
        ));

        let later = catalog.join("z-addon");
        fs::create_dir(&later).unwrap();
        package(&later, "z-addon", b"return nil\n");
        let discovered = discover_addons(&catalog).unwrap();
        assert_eq!(
            discovered
                .iter()
                .map(|package| package.manifest().name.as_str())
                .collect::<Vec<_>>(),
            ["actual-name", "header-tagger", "z-addon"]
        );

        let plain_file = root.path().join("plain-file");
        fs::write(&plain_file, "plain").unwrap();
        assert!(matches!(
            AddonPackage::load(&plain_file),
            Err(AddonError::NotDirectory(_))
        ));
        assert!(matches!(
            AddonPackage::load(root.path().join("does-not-exist")),
            Err(AddonError::Io { .. })
        ));
    }

    #[test]
    fn reports_manifest_and_file_set_errors() {
        let root = tempdir().unwrap();
        fs::write(root.path().join(ADDON_MANIFEST_FILE), "{invalid").unwrap();
        assert!(matches!(
            AddonPackage::load(root.path()),
            Err(AddonError::Manifest { .. })
        ));

        package(root.path(), "header-tagger", b"return nil\n");
        let manifest_path = root.path().join(ADDON_MANIFEST_FILE);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["files"]["missing.lua"] = serde_json::Value::String("a".repeat(64));
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(matches!(
            AddonPackage::load(root.path()),
            Err(AddonError::FileSetMismatch {
                undeclared: None,
                missing: Some(_)
            })
        ));
    }

    #[test]
    fn rejects_stale_temporary_installation_directory() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let catalog = root.path().join("catalog");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&catalog).unwrap();
        package(&source, "temp-addon", b"return nil\n");
        let stale = catalog.join(format!(
            ".temp-addon.1.2.3.installing-{}",
            std::process::id()
        ));
        fs::create_dir(&stale).unwrap();

        assert!(matches!(
            install_addon(&source, &catalog),
            Err(AddonError::TemporaryPathExists(path)) if path == stale
        ));
    }
}
