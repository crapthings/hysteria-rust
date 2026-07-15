use alloc::vec::Vec;

use super::codec::{Codec, Reader};

pub(crate) struct RawClientHello<'a> {
    pub(crate) version_and_random: &'a [u8],
    pub(crate) session_id: &'a [u8],
    pub(crate) cipher_suites: &'a [u8],
    pub(crate) compression: &'a [u8],
    pub(crate) extensions: &'a [u8],
    pub(crate) extensions_offset: usize,
    pub(crate) trailing: &'a [u8],
}

impl<'a> RawClientHello<'a> {
    pub(crate) fn parse(body: &'a [u8]) -> Option<Self> {
        let mut r = Reader::init(body);
        let version_and_random = r.take(2 + 32)?;
        let sid_len = u8::read(&mut r).ok()? as usize;
        let session_id = r.take(sid_len)?;
        let cs_len = u16::read(&mut r).ok()? as usize;
        let cipher_suites = r.take(cs_len)?;
        let comp_len = u8::read(&mut r).ok()? as usize;
        let compression = r.take(comp_len)?;
        let ext_len = u16::read(&mut r).ok()? as usize;
        let extensions_offset = body.len() - r.left();
        let extensions = r.take(ext_len)?;
        let trailing = r.rest();
        Some(Self {
            version_and_random,
            session_id,
            cipher_suites,
            compression,
            extensions,
            extensions_offset,
            trailing,
        })
    }

    pub(crate) fn iter_extensions(&self) -> RawExtensionIter<'a> {
        RawExtensionIter {
            reader: Reader::init(self.extensions),
            total_len: self.extensions.len(),
        }
    }
}

pub(crate) struct RawExtensionIter<'a> {
    reader: Reader<'a>,
    total_len: usize,
}

impl<'a> RawExtensionIter<'a> {
    pub(crate) fn advance_to(&mut self, ext_type: u16) -> Result<RawExtension<'a>, ()> {
        loop {
            let ext = self.next().ok_or(())??;
            if ext.ext_type == ext_type {
                return Ok(ext);
            }
        }
    }
}

impl<'a> Iterator for RawExtensionIter<'a> {
    type Item = Result<RawExtension<'a>, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.reader.any_left() {
            return None;
        }
        let Ok(ext_type) = u16::read(&mut self.reader) else {
            return Some(Err(()));
        };
        let Ok(ext_len) = u16::read(&mut self.reader) else {
            return Some(Err(()));
        };
        let Some(data) = self.reader.take(ext_len as usize) else {
            return Some(Err(()));
        };
        let data_end = self.total_len - self.reader.left();
        Some(Ok(RawExtension {
            ext_type,
            data,
            data_end,
        }))
    }
}

pub(crate) struct RawExtension<'a> {
    pub(crate) ext_type: u16,
    pub(crate) data: &'a [u8],
    pub(crate) data_end: usize,
}

impl RawExtension<'_> {
    pub(crate) fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ext_type.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(self.data);
    }
}
