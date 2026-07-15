use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};

use rufs::{BlockReader, InodeNum, InodeType, Ufs};

const BLOCK_SIZE: usize = 512;
const COPY_BUFFER_SIZE: usize = 1024 * 1024;

struct OffsetFile {
    inner: File,
    base: u64,
}

impl OffsetFile {
    fn open(path: &Path, base: u64) -> io::Result<Self> {
        let mut inner = OpenOptions::new().read(true).open(path)?;
        inner.seek(SeekFrom::Start(base))?;
        Ok(Self { inner, base })
    }
}

impl Read for OffsetFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for OffsetFile {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the UFS image is read-only",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for OffsetFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let absolute = match position {
            SeekFrom::Start(offset) => self
                .base
                .checked_add(offset)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek overflow"))?,
            SeekFrom::Current(offset) => {
                let position = self.inner.seek(SeekFrom::Current(offset))?;
                return position.checked_sub(self.base).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek before UFS image")
                });
            }
            SeekFrom::End(offset) => {
                let end = self.inner.seek(SeekFrom::End(0))?;
                let absolute = i128::from(end) + i128::from(offset);
                if absolute < i128::from(self.base) || absolute > i128::from(u64::MAX) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek outside UFS image",
                    ));
                }
                absolute as u64
            }
        };
        self.inner.seek(SeekFrom::Start(absolute))?;
        Ok(absolute - self.base)
    }
}

struct Extractor {
    ufs: Ufs<OffsetFile>,
    output: PathBuf,
    hard_links: HashMap<u32, PathBuf>,
}

impl Extractor {
    fn new(image: &Path, offset: u64, output: PathBuf) -> io::Result<Self> {
        let image = OffsetFile::open(image, offset)?;
        let reader = BlockReader::new(image, BLOCK_SIZE, false);
        Ok(Self {
            ufs: Ufs::new(reader)?,
            output,
            hard_links: HashMap::new(),
        })
    }

    fn extract_path(&mut self, source: &Path) -> io::Result<()> {
        let mut inode = InodeNum::ROOT;
        let mut relative = PathBuf::new();
        for component in source.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    inode = self.ufs.dir_lookup(inode, name)?;
                    relative.push(name);
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsupported source path: {}", source.display()),
                    ));
                }
            }
        }
        self.extract_inode(inode, &relative)
    }

    fn extract_inode(&mut self, inode: InodeNum, relative: &Path) -> io::Result<()> {
        let metadata = self.ufs.inode_attr(inode)?;
        let destination = self.output.join(relative);
        match metadata.kind {
            InodeType::Directory => {
                fs::create_dir_all(&destination)?;
                let mut entries = Vec::new();
                self.ufs.dir_iter(inode, |name, child, kind| {
                    if name != OsStr::new(".") && name != OsStr::new("..") {
                        entries.push((name.to_owned(), child, kind));
                    }
                    None::<()>
                })?;
                for (name, child, _kind) in entries {
                    if Path::new(&name).components().count() != 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "UFS directory entry is not a single path component",
                        ));
                    }
                    self.extract_inode(child, &relative.join(name))?;
                }
                fs::set_permissions(
                    &destination,
                    fs::Permissions::from_mode(metadata.perm.into()),
                )?;
            }
            InodeType::RegularFile => {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                if let Some(existing) = self.hard_links.get(&inode.get()) {
                    fs::hard_link(existing, &destination)?;
                    return Ok(());
                }
                let mut output = File::create(&destination)?;
                let mut offset = 0_u64;
                let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
                while offset < metadata.size {
                    let remaining =
                        usize::try_from((metadata.size - offset).min(COPY_BUFFER_SIZE as u64))
                            .expect("bounded by the copy buffer size");
                    let read = self
                        .ufs
                        .inode_read(inode, offset, &mut buffer[..remaining])?;
                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("short read from UFS inode {}", inode.get()),
                        ));
                    }
                    output.write_all(&buffer[..read])?;
                    offset += read as u64;
                }
                fs::set_permissions(
                    &destination,
                    fs::Permissions::from_mode(metadata.perm.into()),
                )?;
                self.hard_links.insert(inode.get(), destination);
            }
            InodeType::Symlink => {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                let target = OsString::from_vec(self.ufs.symlink_read(inode)?);
                symlink(target, destination)?;
            }
            InodeType::BlockDevice
            | InodeType::CharDevice
            | InodeType::NamedPipe
            | InodeType::Socket => {}
        }
        Ok(())
    }
}

fn parse_offset(value: &OsStr) -> io::Result<u64> {
    value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset is not UTF-8"))?
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn main() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let image = arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: ufs-extract IMAGE OFFSET OUTPUT PATH...",
        )
    })?;
    let offset =
        parse_offset(&arguments.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing UFS byte offset")
        })?)?;
    let output = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing output directory"))?;
    let paths: Vec<PathBuf> = arguments.map(PathBuf::from).collect();
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one source path is required",
        ));
    }

    fs::create_dir_all(&output)?;
    let mut extractor = Extractor::new(Path::new(&image), offset, PathBuf::from(output))?;
    for path in paths {
        extractor.extract_path(&path)?;
    }
    Ok(())
}
