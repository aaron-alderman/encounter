use crate::{Result, appdev_host_process::interruption, fail};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet, VecDeque}, fs::{self, File, OpenOptions}, io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt}, path::{Component, Path}, time::{Duration, Instant}};

pub(super) const ARCHIVE_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const EXPANDED_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
pub(super) const MEMBER_LIMIT: usize = 100_000;
pub(super) const BLOCK: usize = 512;

pub(super) enum Modes { Private, Dependency }

impl Modes {
    fn directory(&self) -> u32 { match self { Self::Private => 0o700, Self::Dependency => 0o755 } }
    fn file(&self, archived: u64) -> u32 {
        match self { Self::Private => 0o600, Self::Dependency => 0o644 | (archived as u32 & 0o111) }
    }
}

fn mkdir(root: &Path, path: &Path, mode: u32) -> Result<()> {
    let mut target = root.to_owned();
    for part in path.components() {
        target.push(part);
        match fs::DirBuilder::new().mode(mode).create(&target) {
            Ok(()) => fs::set_permissions(&target, fs::Permissions::from_mode(mode))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && target.symlink_metadata()?.is_dir() => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(super) struct Work { deadline: Instant }

impl Work {
    pub(super) fn new(timeout: Duration) -> Self { Self { deadline: Instant::now() + timeout } }
}

impl Work {
    pub(super) fn check(&self) -> Result<()> {
        if interruption().is_some() { return Err(fail("Archive operation interrupted")); }
        if Instant::now() >= self.deadline { return Err(fail("Archive operation exceeded its deadline")); }
        Ok(())
    }

    pub(super) fn copy(&self, input: &mut impl Read, output: &mut impl Write, limit: u64) -> Result<(u64, String)> {
        let mut input = input.take(limit + 1);
        let mut buffer = [0; 65_536];
        let mut size = 0;
        let mut hash = Sha256::new();
        loop {
            self.check()?;
            let count = input.read(&mut buffer)?;
            if count == 0 { break; }
            size += count as u64;
            if size > limit { return Err(fail("Archive operation input exceeded its byte bound")); }
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        Ok((size, hex::encode(hash.finalize())))
    }
}

pub(super) fn input(path: &Path, limit: u64) -> Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit { return Err(fail("Expected a bounded regular Archive operation input")); }
    Ok(file)
}

pub(super) fn create(path: &Path) -> Result<File> {
    let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

pub(super) fn sync_directories(work: &Work, root: &Path) -> Result<()> {
    let mut directories = vec![root.to_owned()];
    while let Some(directory) = directories.pop() {
        work.check()?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { directories.push(entry.path()); }
        }
        File::open(&directory)?.sync_all()?;
    }
    Ok(())
}

fn tar_number(bytes: &[u8]) -> Result<u64> {
    if bytes.first() == Some(&0x80) {
        return bytes[1..].iter().try_fold(0_u64, |value, byte| value.checked_mul(256).and_then(|value| value.checked_add((*byte).into())))
            .ok_or_else(|| fail("archive number exceeds its bound"));
    }
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    if text.is_empty() { Ok(0) } else { Ok(u64::from_str_radix(text, 8)?) }
}

fn tar_string(bytes: &[u8]) -> Result<&str> {
    Ok(std::str::from_utf8(bytes.split(|byte| *byte == 0).next().unwrap_or_default())?)
}

fn tar_path(header: &[u8; BLOCK]) -> Result<String> {
    let name = tar_string(&header[..100])?;
    let prefix = if &header[257..263] == b"ustar\0" { tar_string(&header[345..500])? } else { "" };
    Ok(if prefix.is_empty() { name.to_owned() } else { format!("{prefix}/{name}") })
}

#[derive(Default)]
struct Attributes { path: Option<String>, size: Option<u64>, link: Option<String> }

impl Attributes {
    fn pax(&mut self, mut bytes: &[u8], global: bool, allow_link: bool) -> Result<()> {
        while !bytes.is_empty() {
            let space = bytes.iter().position(|byte| *byte == b' ').ok_or_else(|| fail("Invalid PAX header"))?;
            let length: usize = std::str::from_utf8(&bytes[..space])?.parse()?;
            if length <= space + 2 || length > bytes.len() || bytes[length - 1] != b'\n' {
                return Err(fail("Invalid PAX record size"));
            }
            let (name, value) = std::str::from_utf8(&bytes[space + 1..length - 1])?.split_once('=')
                .ok_or_else(|| fail("Invalid PAX attribute"))?;
            match name {
                "path" if !global && self.path.is_none() => self.path = Some(value.to_owned()),
                "size" if !global && self.size.is_none() => self.size = Some(value.parse()?),
                "linkpath" if allow_link && !global && self.link.is_none() => self.link = Some(value.to_owned()),
                "path" | "size" | "linkpath" | "SCHILY.realsize" | "SCHILY.filetype" => return Err(fail("Unsupported PAX member override")),
                name if name.starts_with("GNU.sparse.") => return Err(fail("Sparse archive members are unsupported")),
                _ => {}
            }
            bytes = &bytes[length..];
        }
        Ok(())
    }
}

fn padding(reader: &mut impl Read, length: u64) -> Result<()> {
    let size = ((BLOCK as u64 - length % BLOCK as u64) % BLOCK as u64) as usize;
    let mut unused = [0; BLOCK];
    reader.read_exact(&mut unused[..size])?;
    Ok(())
}

fn valid_tar_header(header: &mut [u8; BLOCK]) -> Result<()> {
    let checksum = tar_number(&header[148..156])?;
    header[148..156].fill(b' ');
    if checksum != header.iter().map(|byte| u64::from(*byte)).sum::<u64>()
        || !matches!(&header[257..263], b"ustar " | b"ustar\0" | b"\0\0\0\0\0\0") {
        return Err(fail("Invalid tar header"));
    }
    Ok(())
}

pub(super) fn unpack(work: &Work, file: File, output: &Path, modes: Modes,
    mut admit: impl FnMut(&str, bool) -> Result<String>, mut verify: impl FnMut(&str, &str) -> Result<()>) -> Result<(usize, usize)> {
    let mut compressed = GzDecoder::new(BufReader::new(file));
    let mut data = (&mut compressed).take(EXPANDED_LIMIT + 1);
    let mut seen = BTreeSet::new();
    let mut headers = 0;
    let mut verified = 0;
    let mut attributes = Attributes::default();
    let mut pending = false;
    loop {
        work.check()?;
        let mut header = [0; BLOCK];
        data.read_exact(&mut header)?;
        if header == [0; BLOCK] {
            data.read_exact(&mut header)?;
            if pending || header != [0; BLOCK] { return Err(fail("Invalid archive terminator")); }
            break;
        }
        headers += 1;
        if headers > MEMBER_LIMIT * 2 { return Err(fail("archive has too many members")); }
        valid_tar_header(&mut header)?;
        let mut size = tar_number(&header[124..136])?;
        let kind = header[156];
        if matches!(kind, b'L' | b'x' | b'g') {
            if size > 32_768 { return Err(fail("archive metadata exceeds its bound")); }
            let mut bytes = vec![0; size as usize];
            data.read_exact(&mut bytes)?;
            match kind {
                b'L' if attributes.path.is_none() && bytes.last() == Some(&0) => {
                    attributes.path = Some(std::str::from_utf8(&bytes[..bytes.len() - 1])?.to_owned());
                    pending = true;
                }
                b'x' | b'g' => { attributes.pax(&bytes, kind == b'g', false)?; pending |= kind == b'x'; }
                _ => return Err(fail("Invalid long member name")),
            }
            padding(&mut data, size)?;
            continue;
        }
        if !matches!(kind, b'0' | 0 | b'5') || !tar_string(&header[157..257])?.is_empty() {
            return Err(fail("Archive contains a non-regular member"));
        }
        pending = false;
        let name = attributes.path.take().map_or_else(|| tar_path(&header), Ok)?;
        size = attributes.size.take().unwrap_or(size);
        let name = admit(&name, kind == b'5')?;
        let path = Path::new(&name);
        if !path.components().all(|part| matches!(part, Component::Normal(_))) {
            return Err(fail("Expected a normalized archive path"));
        }
        if seen.len() == MEMBER_LIMIT || !seen.insert(name.clone()) {
            return Err(fail("Archive has duplicate or oversized member names"));
        }
        if kind == b'5' {
            if size != 0 { return Err(fail("Archive directory member has file contents")); }
            mkdir(output, path, modes.directory())?;
            continue;
        }
        if name.is_empty() || size >= data.limit() { return Err(fail("Invalid or oversized archive regular member")); }
        let target = output.join(path);
        mkdir(output, path.parent().ok_or_else(|| fail("Missing archive member parent"))?, modes.directory())?;
        let mut file = create(&target)?;
        let (count, digest) = work.copy(&mut (&mut data).take(size), &mut file, size)?;
        if count != size { return Err(fail("Archive member is truncated")); }
        verify(&name, &digest)?;
        file.set_permissions(fs::Permissions::from_mode(modes.file(tar_number(&header[100..108])?)))?;
        file.sync_all()?;
        padding(&mut data, size)?;
        verified += 1;
    }
    let mut padding = [0; 65_536];
    loop {
        work.check()?;
        let count = data.read(&mut padding)?;
        if count == 0 { break; }
        if padding[..count].iter().any(|byte| *byte != 0) { return Err(fail("archive has content after its terminator")); }
    }
    if data.limit() == 0 || !compressed.into_inner().fill_buf()?.is_empty() {
        return Err(fail("archive has oversized or trailing compressed content"));
    }
    Ok((seen.len(), verified))
}

enum ImageMember {
    File { offset: u64, size: u64, mode: u32 },
    Directory,
    Link { target: String, rooted: bool },
    Special,
}

/// Index a flattened image export without extracting or following host filesystem paths.
pub(super) struct ImageArchive {
    file: BufReader<File>,
    members: BTreeMap<String, ImageMember>,
}

impl ImageArchive {
    pub(super) fn open(work: &Work, file: File) -> Result<Self> {
        let length = file.metadata()?.len();
        let mut file = BufReader::new(file);
        let mut members = BTreeMap::new();
        let mut attrs = Attributes::default();
        let mut pending = false;
        let mut headers = 0;
        loop {
            work.check()?;
            let mut header = [0; BLOCK];
            file.read_exact(&mut header)?;
            if header == [0; BLOCK] {
                file.read_exact(&mut header)?;
                if pending || header != [0; BLOCK] { return Err(fail("Invalid image tar terminator")); }
                break;
            }
            headers += 1;
            if headers > MEMBER_LIMIT * 2 { return Err(fail("Image export has too many headers")); }
            valid_tar_header(&mut header)?;
            let kind = header[156];
            let size = tar_number(&header[124..136])?;
            if matches!(kind, b'L' | b'K' | b'x' | b'g') {
                if size > 32_768 { return Err(fail("Image export metadata exceeds its bound")); }
                let mut bytes = vec![0; size as usize];
                file.read_exact(&mut bytes)?;
                match kind {
                    b'L' if attrs.path.is_none() && bytes.last() == Some(&0) => attrs.path = Some(tar_string(&bytes)?.to_owned()),
                    b'K' if attrs.link.is_none() && bytes.last() == Some(&0) => attrs.link = Some(tar_string(&bytes)?.to_owned()),
                    b'x' | b'g' => attrs.pax(&bytes, kind == b'g', true)?,
                    _ => return Err(fail("Invalid image export metadata")),
                }
                pending |= kind != b'g';
                padding(&mut file, size)?;
                continue;
            }
            pending = false;
            let name = attrs.path.take().map_or_else(|| tar_path(&header), Ok)?;
            let name = name.strip_prefix("./").unwrap_or(&name).trim_end_matches('/');
            let size = attrs.size.take().unwrap_or(size);
            let target = attrs.link.take().map_or_else(|| tar_string(&header[157..257]).map(str::to_owned), Ok)?;
            let offset = file.stream_position()?;
            let end = offset.checked_add(size).and_then(|end| end.checked_add((BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64))
                .filter(|end| *end <= length).ok_or_else(|| fail("Image export member is truncated"))?;
            let entry = match kind {
                b'0' | 0 if target.is_empty() => ImageMember::File { offset, size, mode: tar_number(&header[100..108])? as u32 },
                b'5' if size == 0 && target.is_empty() => ImageMember::Directory,
                b'1' | b'2' if size == 0 && !target.is_empty() => ImageMember::Link { target, rooted: kind == b'1' },
                b'3' | b'4' | b'6' if size == 0 && target.is_empty() => ImageMember::Special,
                _ => return Err(fail("Unsupported image export member")),
            };
            if !matches!(name, "" | ".") || !matches!(entry, ImageMember::Directory) {
                if name.is_empty() || name.len() > 4096 || name.split('/').any(|part| matches!(part, "" | "." | "..") || part.contains('\0'))
                    || members.len() == MEMBER_LIMIT || members.insert(name.to_owned(), entry).is_some() {
                    return Err(fail("Invalid or duplicate image export path"));
                }
            }
            file.seek(SeekFrom::Start(end))?;
        }
        let mut tail = [0; 8192];
        loop {
            work.check()?;
            let count = file.read(&mut tail)?;
            if count == 0 { break; }
            if tail[..count].iter().any(|byte| *byte != 0) { return Err(fail("Content after image export terminator")); }
        }
        Ok(Self { file, members })
    }

    pub(super) fn copy(&mut self, work: &Work, path: &str, output: &mut impl Write, limit: u64) -> Result<u32> {
        let mut pending: VecDeque<String> = path.split('/').map(str::to_owned).collect();
        let mut parent = Vec::new();
        let mut links = 0;
        while let Some(part) = pending.pop_front() {
            work.check()?;
            match part.as_str() {
                "" | "." => continue,
                ".." if parent.pop().is_some() => continue,
                ".." => return Err(fail("Image member link escapes the image root")),
                _ => {}
            }
            parent.push(part);
            match self.members.get(&parent.join("/")) {
                Some(ImageMember::Link { target, rooted }) => {
                    links += 1;
                    if links > 40 || target.contains('\0') { return Err(fail("Invalid image link chain")); }
                    parent.pop();
                    if *rooted || target.starts_with('/') { parent.clear(); }
                    for part in target.rsplit('/') { pending.push_front(part.to_owned()); }
                }
                Some(ImageMember::Directory) => {}
                Some(ImageMember::File { offset, size, mode }) if pending.is_empty() && *size <= limit => {
                    self.file.seek(SeekFrom::Start(*offset))?;
                    let (count, _) = work.copy(&mut (&mut self.file).take(*size), output, *size)?;
                    if count != *size { return Err(fail("Image export member is truncated")); }
                    return Ok(*mode);
                }
                _ => return Err(fail(format!("Image export does not contain the bounded regular member {path}"))),
            }
        }
        Err(fail(format!("Image export does not contain a regular member {path}")))
    }
}

#[cfg(test)]
#[test]
fn image_export_links_resolve_only_inside_the_indexed_image() -> Result<()> {
    fn member(tar: &mut File, name: &str, kind: u8, target: &str, data: &[u8]) -> Result<()> {
        let mut header = [0_u8; BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000755\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[148..156].fill(b' ');
        header[156] = kind;
        header[157..157 + target.len()].copy_from_slice(target.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar.write_all(&header)?;
        tar.write_all(data)?;
        tar.write_all(&[0; BLOCK][..(BLOCK - data.len() % BLOCK) % BLOCK])?;
        Ok(())
    }
    let scratch = crate::appdev_host_process::Scratch::create(&std::env::temp_dir(), "image-archive-test-")?;
    let mut tar = create(&scratch.path().join("base.tar"))?;
    member(&mut tar, "usr", b'5', "", b"")?;
    member(&mut tar, "usr/lib", b'5', "", b"")?;
    member(&mut tar, "usr/lib/actual", b'0', "", b"library")?;
    member(&mut tar, "usr/lib/hard", b'1', "usr/lib/actual", b"")?;
    member(&mut tar, "lib", b'2', "/usr/lib", b"")?;
    member(&mut tar, "usr/lib/escape", b'2', "../../../etc/passwd", b"")?;
    member(&mut tar, "usr/lib/missing", b'2', "/etc/passwd", b"")?;
    member(&mut tar, "usr/lib/loop", b'2', "loop", b"")?;
    tar.write_all(&[0; BLOCK * 2])?;
    tar.rewind()?;
    let work = Work::new(Duration::from_secs(5));
    let mut image = ImageArchive::open(&work, tar)?;
    let mut output = Vec::new();
    assert_eq!(image.copy(&work, "lib/hard", &mut output, 16)?, 0o755);
    assert_eq!(output, b"library");
    for path in ["lib/escape", "lib/missing", "lib/loop", "lib/actual/child"] {
        assert!(image.copy(&work, path, &mut io::sink(), 16).is_err(), "{path}");
    }
    assert!(image.copy(&work, "lib/actual", &mut io::sink(), 6).is_err());
    Ok(())
}
