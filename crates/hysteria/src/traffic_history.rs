//! Opt-in, GUI-owned daily JSON storage. Call synchronous I/O off the UI/async thread.
use crate::{
    CliError, Result,
    client_traffic::{TrafficSnapshot, TrafficTotals},
};
use chrono::{DateTime, Days, FixedOffset, NaiveDate};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_FILES: usize = 4096;
const MAX_RETIRED: usize = 256;
/// One day's totals and an atomic replay checkpoint. No destinations or credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailyTraffic {
    pub schema_version: u8,
    pub date: String,
    /// Fixed UTC offset, for example +08:00. DST/IANA zone changes need a new store.
    pub utc_offset: String,
    pub updated_at: String,
    pub traffic: TrafficTotals,
    pub checkpoint: TrafficSnapshot,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_sessions: Vec<String>,
}
/// One writer owns a dedicated private directory for one logical client's history.
/// Different concurrently active clients must use different directories.
pub struct DailyTrafficStore {
    directory: PathBuf,
    offset: FixedOffset,
    offset_text: String,
    _lock: fs::File,
}
impl DailyTrafficStore {
    /// Open/create private storage, acquire a nonblocking lifetime lock and validate
    /// existing daily files. Parent directories must be trusted; do not move/edit
    /// this directory while open. Windows inherits the parent directory ACL.
    /// # Errors
    /// Rejects relative paths, unsafe storage, busy stores and invalid existing records.
    pub fn open(directory: impl Into<PathBuf>, utc_offset: &str) -> Result<Self> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(CliError::new("traffic history directory must be absolute"));
        }
        let offset = parse_offset(utc_offset)?;
        if !directory.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&directory)?;
        }
        check_directory(&directory)?;
        let lock_path = directory.join(".lock");
        check_destination(&lock_path)?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&lock_path)?;
        lock.try_lock()
            .map_err(|_| CliError::new("traffic history store is busy"))?;
        let store = Self {
            directory,
            offset,
            offset_text: utc_offset.into(),
            _lock: lock,
        };
        for date in store.list_days()? {
            store.read_required(&date)?;
        }
        Ok(store)
    }
    /// Sorted canonical dates; unrelated files are never changed.
    /// # Errors
    /// Rejects unsafe daily entries, malformed date filenames or too many files.
    pub fn list_days(&self) -> Result<Vec<String>> {
        check_directory(&self.directory)?;
        let mut dates = Vec::new();
        for (count, entry) in fs::read_dir(&self.directory)?.enumerate() {
            if count >= MAX_FILES {
                return Err(CliError::new(
                    "traffic history directory exceeds entry limit",
                ));
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(date) = name.strip_suffix(".json") else {
                continue;
            };
            if date.len() != 10 || date.as_bytes()[4] != b'-' || date.as_bytes()[7] != b'-' {
                continue;
            }
            date_value(date)?;
            check_file(&entry.path())?;
            dates.push(date.to_owned());
        }
        dates.sort();
        Ok(dates)
    }
    /// Read one validated day without changing it.
    /// # Errors
    /// Rejects invalid dates, schemas, permissions and corrupt records.
    pub fn read_day(&self, date: &str) -> Result<Option<DailyTraffic>> {
        date_value(date)?;
        check_directory(&self.directory)?;
        match fs::symlink_metadata(self.path(date)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => self.read_required(date).map(Some),
        }
    }
    fn path(&self, date: &str) -> PathBuf {
        self.directory.join(format!("{date}.json"))
    }
    fn read_required(&self, date: &str) -> Result<DailyTraffic> {
        let path = self.path(date);
        check_file(&path)?;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(CliError::new("traffic history file exceeds size limit"));
        }
        let shape: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| CliError::new("invalid traffic history JSON; original file preserved"))?;
        if !shape.is_object()
            || !shape["traffic"].is_object()
            || !shape["traffic"]["direct"].is_object()
            || !shape["traffic"]["proxy"].is_object()
            || !shape["checkpoint"].is_object()
            || !shape["checkpoint"]["traffic"].is_object()
            || !shape["checkpoint"]["traffic"]["direct"].is_object()
            || !shape["checkpoint"]["traffic"]["proxy"].is_object()
        {
            return Err(CliError::new(
                "traffic history fields must use the versioned object format",
            ));
        }
        let record: DailyTraffic = serde_json::from_slice(&bytes)
            .map_err(|_| CliError::new("invalid traffic history JSON; original file preserved"))?;
        self.validate(&record, date)?;
        Ok(record)
    }
    fn validate(&self, record: &DailyTraffic, date: &str) -> Result<()> {
        if record.schema_version != 1
            || record.date != date
            || record.utc_offset != self.offset_text
            || record.retired_sessions.len() > MAX_RETIRED
        {
            return Err(CliError::new(
                "traffic history schema, date, offset or session limit is invalid",
            ));
        }
        date_value(date)?;
        let sampled = record.checkpoint.validate()?;
        let updated = DateTime::parse_from_rfc3339(&record.updated_at)
            .map_err(|_| CliError::new("invalid traffic history update time"))?;
        if updated != sampled
            || updated.offset() != &self.offset
            || updated.date_naive().to_string() != date
        {
            return Err(CliError::new(
                "traffic history timestamp does not match its checkpoint/day",
            ));
        }
        let unique: HashSet<_> = record.retired_sessions.iter().collect();
        if unique.len() != record.retired_sessions.len()
            || record
                .retired_sessions
                .iter()
                .any(|s| !valid_session(s) || s == &record.checkpoint.session_id)
        {
            return Err(CliError::new("invalid retired traffic session identities"));
        }
        Ok(())
    }
    /// Atomically record a cumulative sample. The first sample of each new session
    /// establishes a baseline (no guessed backfill). Retry the identical sample
    /// after an uncertain write: the on-disk checkpoint prevents double counting.
    /// A cross-midnight interval belongs entirely to the ending sample's day.
    /// # Errors
    /// Rejects clock rollback, decreasing counters, retired sessions and unsafe files.
    pub fn record(&mut self, snapshot: &TrafficSnapshot) -> Result<DailyTraffic> {
        self.record_with_sync(snapshot, sync_directory)
    }
    fn record_with_sync(
        &mut self,
        snapshot: &TrafficSnapshot,
        sync: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<DailyTraffic> {
        let sampled = snapshot.validate()?;
        let date = sampled.with_timezone(&self.offset).date_naive().to_string();
        date_value(&date)?;
        let mut latest: Option<DailyTraffic> = None;
        let mut today = None;
        let mut seen = false;
        for day in self.list_days()? {
            let record = self.read_required(&day)?;
            seen |= record.checkpoint.session_id == snapshot.session_id
                || record.retired_sessions.contains(&snapshot.session_id);
            if day == date {
                today = Some(record.clone());
            }
            latest = Some(record);
        }
        let mut delta = TrafficTotals::default();
        if let Some(previous) = &latest {
            if sampled < previous.checkpoint.validate()? || date < previous.date {
                return Err(CliError::new(
                    "traffic sample clock moved backwards; history preserved",
                ));
            }
            if snapshot.session_id == previous.checkpoint.session_id {
                if snapshot.elapsed_ms < previous.checkpoint.elapsed_ms {
                    return Err(CliError::new("traffic sample elapsed time decreased"));
                }
                delta = snapshot
                    .traffic
                    .subtract(previous.checkpoint.traffic)
                    .ok_or_else(|| CliError::new("traffic counters decreased within a session"))?;
                if &previous.checkpoint == snapshot {
                    sync(&self.directory)?;
                    return Ok(previous.clone());
                }
            } else if seen {
                return Err(CliError::new("traffic sample belongs to a retired session"));
            }
        }
        let mut record = today.unwrap_or_else(|| DailyTraffic {
            schema_version: 1,
            date: date.clone(),
            utc_offset: self.offset_text.clone(),
            updated_at: String::new(),
            traffic: TrafficTotals::default(),
            checkpoint: snapshot.clone(),
            retired_sessions: Vec::new(),
        });
        if let Some(previous) = latest
            && previous.checkpoint.session_id != snapshot.session_id
            && !record
                .retired_sessions
                .contains(&previous.checkpoint.session_id)
        {
            record.retired_sessions.push(previous.checkpoint.session_id);
        }
        record.traffic = record
            .traffic
            .add(delta)
            .ok_or_else(|| CliError::new("daily traffic counter overflow"))?;
        record.updated_at = sampled
            .with_timezone(&self.offset)
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false);
        record.checkpoint = snapshot.clone();
        self.validate(&record, &date)?;
        let mut bytes = serde_json::to_vec_pretty(&record)
            .map_err(|_| CliError::new("cannot encode traffic history"))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(CliError::new("traffic history record exceeds size limit"));
        }
        check_destination(&self.path(&date))?;
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(self.path(&date))
            .map_err(|e| CliError::new(format!("cannot publish traffic history: {}", e.error)))?;
        // A failure here can follow a successful replacement. Always re-read on retry.
        sync(&self.directory)?;
        Ok(record)
    }
    /// Explicitly keep the reference day and previous 89 days. Validate all records
    /// before deleting any; ignore unrelated files and future records.
    /// # Errors
    /// Returns validation/storage errors. A deletion error can follow earlier deletions.
    pub fn prune(&mut self, reference_day: &str) -> Result<usize> {
        let cutoff = date_value(reference_day)?
            .checked_sub_days(Days::new(89))
            .ok_or_else(|| CliError::new("invalid retention reference date"))?;
        let mut obsolete = Vec::new();
        for day in self.list_days()? {
            self.read_required(&day)?;
            if date_value(&day)? < cutoff {
                obsolete.push(self.path(&day));
            }
        }
        for path in &obsolete {
            check_file(path)?;
            fs::remove_file(path)?;
        }
        if !obsolete.is_empty() {
            sync_directory(&self.directory)?;
        }
        Ok(obsolete.len())
    }
}
fn date_value(date: &str) -> Result<NaiveDate> {
    let parsed = NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map_err(|_| CliError::new("history date must be YYYY-MM-DD"))?;
    if date.len() != 10 || parsed.to_string() != date {
        return Err(CliError::new("history date must be YYYY-MM-DD"));
    }
    Ok(parsed)
}
fn valid_session(session: &str) -> bool {
    session.len() == 32
        && session
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn parse_offset(value: &str) -> Result<FixedOffset> {
    let invalid = || CliError::new("history UTC offset must be +HH:MM or -HH:MM, within 14 hours");
    let bytes = value.as_bytes();
    if bytes.len() != 6
        || !matches!(bytes[0], b'+' | b'-')
        || bytes[3] != b':'
        || ![bytes[1], bytes[2], bytes[4], bytes[5]]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    let hours = i32::from(bytes[1] - b'0') * 10 + i32::from(bytes[2] - b'0');
    let minutes = i32::from(bytes[4] - b'0') * 10 + i32::from(bytes[5] - b'0');
    if minutes >= 60 || hours > 14 || (hours == 14 && minutes != 0) || value == "-00:00" {
        return Err(invalid());
    }
    FixedOffset::east_opt((hours * 3600 + minutes * 60) * if bytes[0] == b'-' { -1 } else { 1 })
        .ok_or_else(invalid)
}
fn check_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(CliError::new(
            "history directory must be real, not a symlink",
        ));
    }
    check_private(&metadata)
}
fn check_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(CliError::new(
            "history entry must be a regular file, not a symlink",
        ));
    }
    check_private(&metadata)
}
fn check_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn check_private(metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::new(
                "history storage must be private: directories 0700 and files 0600",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}
fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(session: u8, time: &str, elapsed: u64, bytes: u64) -> TrafficSnapshot {
        TrafficSnapshot {
            schema_version: 1,
            session_id: format!("{session:032x}"),
            sampled_at: time.into(),
            elapsed_ms: elapsed,
            traffic: TrafficTotals {
                direct: crate::client_traffic::ByteTotals {
                    upload_bytes: bytes,
                    download_bytes: bytes * 2,
                },
                proxy: crate::client_traffic::ByteTotals::default(),
            },
        }
    }
    #[test]
    fn retry_restart_and_uncertain_publish_do_not_double_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DailyTrafficStore::open(dir.path().join("history"), "+08:00").unwrap();
        let baseline = sample(1, "2026-11-12T01:00:00Z", 0, 10);
        store.record(&baseline).unwrap();
        let next = sample(1, "2026-11-12T01:01:00Z", 60_000, 110);
        assert_eq!(
            store.record(&next).unwrap().traffic.direct.upload_bytes,
            100
        );
        assert_eq!(
            store.record(&next).unwrap().traffic.direct.upload_bytes,
            100
        );
        drop(store);
        let mut store = DailyTrafficStore::open(dir.path().join("history"), "+08:00").unwrap();
        let next = sample(1, "2026-11-12T01:02:00Z", 120_000, 210);
        assert!(
            store
                .record_with_sync(&next, |_| Err(io::Error::other(
                    "injected directory sync failure"
                )))
                .is_err()
        );
        assert!(
            store
                .record_with_sync(&next, |_| Err(io::Error::other("sync still failing")))
                .is_err()
        );
        assert_eq!(
            store.record(&next).unwrap().traffic.direct.upload_bytes,
            200
        );
        assert_eq!(
            store
                .read_day("2026-11-12")
                .unwrap()
                .unwrap()
                .traffic
                .direct
                .download_bytes,
            400
        );
        assert!(store.read_day("../other").is_err());
        assert!(DailyTrafficStore::open(dir.path().join("history"), "+08:00").is_err());
        drop(store);
        assert!(DailyTrafficStore::open(dir.path().join("history"), "+00:00").is_err());
    }
    #[test]
    fn midnight_new_session_and_rollback_are_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DailyTrafficStore::open(dir.path().join("history"), "+08:00").unwrap();
        store
            .record(&sample(1, "2026-11-12T15:59:50Z", 0, 0))
            .unwrap();
        store
            .record(&sample(1, "2026-11-12T15:59:55Z", 5000, 100))
            .unwrap();
        let record = store
            .record(&sample(1, "2026-11-12T16:00:05Z", 15000, 150))
            .unwrap();
        assert_eq!(record.date, "2026-11-13");
        assert_eq!(record.traffic.direct.upload_bytes, 50);
        assert_eq!(
            store
                .read_day("2026-11-12")
                .unwrap()
                .unwrap()
                .traffic
                .direct
                .upload_bytes,
            100
        );
        assert_eq!(
            store
                .record(&sample(2, "2026-11-12T16:00:06Z", 0, 10))
                .unwrap()
                .traffic
                .direct
                .upload_bytes,
            50
        );
        assert_eq!(
            store
                .record(&sample(2, "2026-11-12T16:00:07Z", 1000, 20))
                .unwrap()
                .traffic
                .direct
                .upload_bytes,
            60
        );
        let path = store.path("2026-11-13");
        let original = fs::read(&path).unwrap();
        for bad in [
            sample(1, "2026-11-12T16:00:08Z", 18000, 160),
            sample(2, "2026-11-12T15:00:00Z", 2000, 30),
            sample(2, "2026-11-12T16:00:08Z", 2000, 5),
            sample(2, "2026-11-12T16:00:08Z", 500, 30),
        ] {
            assert!(store.record(&bad).is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }
    #[test]
    fn corrupt_schema_duplicate_fields_and_noninteger_counts_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DailyTrafficStore::open(dir.path().join("history"), "+00:00").unwrap();
        let first = sample(1, "2026-11-12T00:00:00Z", 0, 0);
        store.record(&first).unwrap();
        let path = store.path("2026-11-12");
        let original = fs::read_to_string(&path).unwrap();
        let cases = [
            "{broken".to_owned(),
            original.replacen("\"schema_version\": 1", "\"schema_version\": 99", 1),
            original.replacen("\"upload_bytes\": 0", "\"upload_bytes\": -1", 1),
            original.replacen("\"upload_bytes\": 0", "\"upload_bytes\": 0.5", 1),
            original.replacen(
                "\"schema_version\": 1",
                "\"schema_version\": 1, \"schema_version\": 1",
                1,
            ),
            original.replacen("\"traffic\": {", "\"unknown\": true, \"traffic\": {", 1),
            "x".repeat(usize::try_from(MAX_FILE_BYTES + 1).unwrap()),
        ];
        for content in cases {
            fs::write(&path, &content).unwrap();
            assert!(
                store
                    .record(&sample(1, "2026-11-12T00:01:00Z", 60_000, 1))
                    .is_err()
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), content);
        }
    }
    #[test]
    fn pruning_validates_first_and_ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DailyTrafficStore::open(dir.path().join("history"), "+00:00").unwrap();
        for (elapsed, date) in ["2026-08-01", "2026-08-20", "2026-11-12"]
            .into_iter()
            .enumerate()
        {
            store
                .record(&sample(
                    1,
                    &format!("{date}T00:00:00Z"),
                    elapsed as u64,
                    elapsed as u64,
                ))
                .unwrap();
        }
        let recent = store.path("2026-11-12");
        let saved = fs::read(&recent).unwrap();
        fs::write(&recent, "broken").unwrap();
        assert!(store.prune("2026-11-12").is_err());
        assert!(store.path("2026-08-01").exists());
        fs::write(&recent, saved).unwrap();
        fs::write(store.directory.join("notes.json"), "leave me").unwrap();
        assert_eq!(store.prune("2026-11-12").unwrap(), 1);
        assert_eq!(store.list_days().unwrap(), vec!["2026-08-20", "2026-11-12"]);
        assert_eq!(
            fs::read_to_string(store.directory.join("notes.json")).unwrap(),
            "leave me"
        );
    }
    #[cfg(unix)]
    #[test]
    fn private_modes_and_symlink_refusal() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("history");
        let mut store = DailyTrafficStore::open(&root, "+00:00").unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        store
            .record(&sample(1, "2026-11-12T00:00:00Z", 0, 0))
            .unwrap();
        let path = store.path("2026-11-12");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read_day("2026-11-12").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&path, store.path("2026-11-13")).unwrap();
        assert!(store.list_days().is_err());
        drop(store);
        let alias = dir.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(DailyTrafficStore::open(alias, "+00:00").is_err());
    }
}
