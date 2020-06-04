use std::io::Read;
use std::mem;

use anyhow::Result;
use foreign_types::ForeignTypeRef;
use libc::c_uint;

use crate::common::{Block, DatabaseRef, Streaming, Vectored};
use crate::errors::AsResult;
use crate::ffi;
use crate::runtime::{split_closure, ScratchRef, StreamRef};

/// Indicating whether or not matching should continue on the target data.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Matching {
    /// The matching should continue
    Continue = 0,
    /// The matching should cease
    Terminate = 1,
}

impl Default for Matching {
    fn default() -> Self {
        Matching::Continue
    }
}

impl DatabaseRef<Block> {
    /// The block (non-streaming) regular expression scanner.
    ///
    /// This is the function call in which the actual pattern matching takes place for block-mode pattern databases.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use hyperscan::prelude::*;
    /// let db: BlockDatabase = pattern! {"test"; CASELESS | SOM_LEFTMOST}.build().unwrap();
    /// let s = db.alloc_scratch().unwrap();
    /// let mut matches = vec![];
    ///
    /// db.scan("foo test bar", &s, |_, from, to, _| {
    ///     matches.push(from..to);
    ///     Matching::Continue
    /// }).unwrap();
    ///
    /// assert_eq!(matches, vec![4..8]);
    /// ```
    pub fn scan<T, F>(&self, data: T, scratch: &ScratchRef, mut on_match_event: F) -> Result<()>
    where
        T: AsRef<[u8]>,
        F: FnMut(u32, u64, u64, u32) -> Matching,
    {
        let data = data.as_ref();
        let (callback, userdata) = unsafe { split_closure(&mut on_match_event) };

        unsafe {
            ffi::hs_scan(
                self.as_ptr(),
                data.as_ptr() as *const i8,
                data.len() as u32,
                0,
                scratch.as_ptr(),
                Some(mem::transmute(callback)),
                userdata,
            )
            .ok()
        }
    }
}

impl DatabaseRef<Vectored> {
    /// The vectored regular expression scanner.
    ///
    /// This is the function call in which the actual pattern matching takes place for vectoring-mode pattern databases.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use hyperscan::prelude::*;
    /// let db: VectoredDatabase = pattern!{"test"; CASELESS|SOM_LEFTMOST}.build().unwrap();
    /// let s = db.alloc_scratch().unwrap();
    ///
    /// let mut matches = vec![];
    ///
    /// db.scan(vec!["foo", "test", "bar"], &s, |id, from, to, _| {
    ///     matches.push(from..to);
    ///     Matching::Continue
    /// }).unwrap();
    ///
    /// assert_eq!(matches, vec![3..7]);
    /// ```
    pub fn scan<I, T, F>(&self, data: I, scratch: &ScratchRef, mut on_match_event: F) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
        F: FnMut(u32, u64, u64, u32) -> Matching,
    {
        let (ptrs, lens): (Vec<_>, Vec<_>) = data
            .into_iter()
            .map(|buf| {
                let buf = buf.as_ref();

                (buf.as_ptr() as *const i8, buf.len() as c_uint)
            })
            .unzip();
        let (callback, userdata) = unsafe { split_closure(&mut on_match_event) };

        unsafe {
            ffi::hs_scan_vector(
                self.as_ptr(),
                ptrs.as_slice().as_ptr() as *const *const i8,
                lens.as_slice().as_ptr() as *const _,
                ptrs.len() as u32,
                0,
                scratch.as_ptr(),
                Some(mem::transmute(callback)),
                userdata,
            )
            .ok()
        }
    }
}

const SCAN_BUF_SIZE: usize = 4096;

impl DatabaseRef<Streaming> {
    /// Pattern matching takes place for stream-mode pattern databases.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use std::io::Cursor;
    /// # use hyperscan::prelude::*;
    /// const SCAN_BUF_SIZE: usize = 4096;
    /// let mut buf = String::from_utf8(vec![b'x'; SCAN_BUF_SIZE - 2]).unwrap();
    ///
    /// buf.push_str("baaab");
    ///
    /// let db: StreamingDatabase = pattern! { "a+"; SOM_LEFTMOST }.build().unwrap();
    /// let s = db.alloc_scratch().unwrap();
    /// let mut cur = Cursor::new(buf.as_bytes());
    /// let mut matches = vec![];
    ///
    /// db.scan(&mut cur, &s, |_, from, to, _| {
    ///     matches.push((from, to));
    ///
    ///     Matching::Continue
    /// })
    /// .unwrap();
    ///
    /// assert_eq!(matches, vec![(4095, 4096), (4095, 4097), (4095, 4098)]);
    /// ```
    pub fn scan<R, F>(&self, reader: &mut R, scratch: &ScratchRef, mut on_match_event: F) -> Result<()>
    where
        R: Read,
        F: FnMut(u32, u64, u64, u32) -> Matching,
    {
        let stream = self.open_stream()?;
        let mut buf = [0; SCAN_BUF_SIZE];

        while let Ok(len) = reader.read(&mut buf[..]) {
            if len == 0 {
                break;
            }

            stream.scan(&buf[..len], scratch, &mut on_match_event)?;
        }

        stream.close(scratch, Some(&mut on_match_event))
    }
}

impl StreamRef {
    /// Write data to be scanned to the opened stream.
    ///
    /// This is the function call in which the actual pattern matching takes place as data is written to the stream.
    /// Matches will be returned via the `on_match_event` callback supplied.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use hyperscan::prelude::*;
    /// let db: StreamingDatabase = pattern! {"test"; SOM_LEFTMOST}.build().unwrap();
    ///
    /// let s = db.alloc_scratch().unwrap();
    /// let st = db.open_stream().unwrap();
    ///
    /// let data = vec!["foo t", "es", "t bar"];
    /// let mut matches = vec![];
    ///
    /// let mut callback = |_, from, to, _| {
    ///     matches.push((from, to));
    ///
    ///     Matching::Continue
    /// };
    ///
    /// for d in data {
    ///     st.scan(d, &s, &mut callback).unwrap();
    /// }
    ///
    /// st.close(&s, Some(&mut callback)).unwrap();
    ///
    /// assert_eq!(matches, vec![(4, 8)]);
    /// ```
    pub fn scan<T, F>(&self, data: T, scratch: &ScratchRef, mut on_match_event: F) -> Result<()>
    where
        T: AsRef<[u8]>,
        F: FnMut(u32, u64, u64, u32) -> Matching,
    {
        let data = data.as_ref();
        let (callback, userdata) = unsafe { split_closure(&mut on_match_event) };

        unsafe {
            ffi::hs_scan_stream(
                self.as_ptr(),
                data.as_ptr() as *const i8,
                data.len() as u32,
                0,
                scratch.as_ptr(),
                Some(mem::transmute(callback)),
                userdata,
            )
            .ok()
        }
    }
}
