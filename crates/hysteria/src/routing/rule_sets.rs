//! Explicit file loading produces immutable snapshots; compilation and routing never read files.
use super::{HostMatcher, MAX_RULE_BYTES, MembershipIndex, RoutingConfig, compile_matchers};
use crate::{CliError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_SETS: usize = 64;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 4 * MAX_FILE_BYTES;
const MAX_SET_MATCHERS: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    pub file: PathBuf,
    #[serde(skip)]
    loaded: Option<Arc<LoadedSet>>,
}
impl RuleSetConfig {
    /// Creates an unloaded local rule-set reference. Call `RoutingConfig::load_rule_sets` before compiling.
    #[must_use]
    pub fn from_file(file: impl Into<PathBuf>) -> Self {
        Self {
            file: file.into(),
            loaded: None,
        }
    }
    pub(super) fn snapshot(&self) -> Result<&Arc<LoadedSet>> {
        let Some(loaded) = &self.loaded else {
            return Err(CliError::new(
                "rule-set files are not loaded; use ClientConfig::load or RoutingConfig::load_rule_sets before compiling",
            ));
        };
        if loaded.configured_file != self.file {
            return Err(CliError::new(
                "rule-set file changed after loading; reload rule-set files",
            ));
        }
        Ok(loaded)
    }
}

pub(super) struct LoadedSet {
    configured_file: PathBuf,
    pub matchers: Arc<[HostMatcher]>,
    pub index: Option<Box<MembershipIndex>>,
    pub source: Arc<SetSource>,
}
impl std::fmt::Debug for LoadedSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSet")
            .field("configured_file", &self.configured_file)
            .field("source", &self.source)
            .field("matchers", &self.matchers.len())
            .field("index", &self.index.is_some())
            .finish()
    }
}
#[derive(Debug)]
pub(super) struct SetSource {
    pub name: String,
    pub file: PathBuf,
    pub lines: Vec<usize>,
}

pub(super) fn deserialize_sets<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, RuleSetConfig>, D::Error> {
    struct SetsVisitor;
    impl<'de> serde::de::Visitor<'de> for SetsVisitor {
        type Value = BTreeMap<String, RuleSetConfig>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map of unique local rule-set names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut sets = BTreeMap::new();
            while let Some(name) = map.next_key::<String>()? {
                if sets.contains_key(&name) {
                    return Err(serde::de::Error::custom("duplicate routing rule-set name"));
                }
                if sets.len() == MAX_SETS {
                    return Err(serde::de::Error::custom("routing.ruleSets exceeds 64 sets"));
                }
                sets.insert(name, map.next_value()?);
            }
            Ok(sets)
        }
    }
    deserializer.deserialize_map(SetsVisitor)
}

pub(super) fn validate_names(sets: &BTreeMap<String, RuleSetConfig>) -> Result<()> {
    if sets.len() > MAX_SETS {
        return Err(CliError::new("routing.ruleSets exceeds 64 sets"));
    }
    for (name, set) in sets {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        {
            return Err(CliError::new(
                "routing.ruleSets names must contain 1–64 ASCII letters, digits, underscores or hyphens",
            ));
        }
        if set.file.as_os_str().is_empty()
            || set.file.as_os_str().len() > MAX_RULE_BYTES
            || set.file.to_string_lossy().contains("://")
        {
            return Err(CliError::new(format!(
                "routing.ruleSets[{name:?}].file must be a nonempty local path of at most {MAX_RULE_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

impl RoutingConfig {
    /// Loads and validates all declared local rule sets into an immutable snapshot.
    /// Relative paths require a base directory; stdin/embedded callers can use absolute paths with `None`.
    /// Existing snapshots are replaced only after every file succeeds. No network fetch or file write occurs.
    /// # Errors
    /// Rejects invalid paths, non-regular/symlink files, invalid UTF-8/matchers, empty sets and resource limits.
    pub fn load_rule_sets(&mut self, base: Option<&Path>) -> Result<()> {
        self.validate_header()?;
        let mut snapshots = Vec::with_capacity(self.rule_sets.len());
        let mut total_bytes = 0;
        let mut total_matchers = 0;
        for (name, set) in &self.rule_sets {
            let path = resolve_path(&set.file, base).map_err(|error| {
                CliError::new(format!("routing.ruleSets[{name:?}]: {error}")).with_source(error)
            })?;
            let (snapshot, bytes) = read_set(name, &set.file, &path)?;
            total_bytes += bytes;
            total_matchers += snapshot.matchers.len();
            if total_bytes > MAX_TOTAL_BYTES || total_matchers > MAX_SET_MATCHERS {
                return Err(CliError::new(
                    "routing.ruleSets exceeds the combined 4 MiB or 4096-matcher limit",
                ));
            }
            snapshots.push(Arc::new(snapshot));
        }
        // Commit in the same BTreeMap order only after every file has passed.
        for (set, snapshot) in self.rule_sets.values_mut().zip(snapshots) {
            set.loaded = Some(snapshot);
        }
        Ok(())
    }
}
fn resolve_path(file: &Path, base: Option<&Path>) -> Result<PathBuf> {
    if file.is_absolute() {
        return Ok(file.to_owned());
    }
    let base = base.ok_or_else(|| CliError::new("relative rule-set paths require a configuration file directory; use absolute paths with stdin"))?;
    let path = base.join(file);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(std::env::current_dir()?.join(path))
}
fn read_set(name: &str, configured_file: &Path, path: &Path) -> Result<(LoadedSet, usize)> {
    let error = |message: &str| {
        CliError::new(format!(
            "routing.ruleSets[{name:?}] file {}: {message}",
            path.display()
        ))
    };
    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| error("cannot read file metadata").with_source(cause))?;
    if !metadata.is_file() {
        return Err(error(
            "expected a regular file, not a symlink or special file",
        ));
    }
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(error("file exceeds 1 MiB"));
    }
    let file =
        fs::File::open(path).map_err(|cause| error("cannot open file").with_source(cause))?;
    if !file
        .metadata()
        .map_err(|cause| error("cannot read open file metadata").with_source(cause))?
        .is_file()
    {
        return Err(error("expected a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|cause| error("cannot read file").with_source(cause))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(error("file exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| error("expected UTF-8 text"))?;
    let mut matchers = Vec::new();
    let mut lines = Vec::new();
    for (index, line) in text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .enumerate()
    {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let invalid = || {
            error(&format!(
                "line {}: expected a host matcher; actions, protocol filters and nested sets are not allowed",
                index + 1
            ))
        };
        if line.len() > MAX_RULE_BYTES || line.contains([',', '(', ')']) || line.starts_with("set:")
        {
            return Err(invalid());
        }
        let compiled = compile_matchers(line, index + 1).map_err(|_| invalid())?;
        lines.extend(std::iter::repeat_n(index + 1, compiled.len()));
        matchers.extend(compiled);
        if matchers.len() > MAX_SET_MATCHERS {
            return Err(error("file exceeds 4096 matchers"));
        }
    }
    if matchers.is_empty() {
        return Err(error("rule set must contain at least one matcher"));
    }
    Ok((
        LoadedSet {
            configured_file: configured_file.to_owned(),
            index: MembershipIndex::for_matchers(&matchers),
            matchers: matchers.into(),
            source: Arc::new(SetSource {
                name: name.to_owned(),
                file: path.to_owned(),
                lines,
            }),
        },
        bytes.len(),
    ))
}

#[cfg(test)]
#[path = "rule_sets_tests.rs"]
mod tests;
