use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{self, Cursor};

pub struct SafeBytesMut {
    buf: BytesMut,
}

impl SafeBytesMut {
    // سازنده برای ایجاد یک SafeBytesMut جدید با ظرفیت مشخص
    pub fn new(capacity: usize) -> Self {
        SafeBytesMut {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    // متدهای افزودن داده به بافر
    pub fn put(&mut self, data: &[u8]) {
        self.buf.put(data);
    }

    pub fn put_u8(&mut self, n: u8) {
        self.buf.put_u8(n);
    }

    pub fn put_u16(&mut self, n: u16) {
        self.buf.put_u16(n);
    }

    pub fn put_u32(&mut self, n: u32) {
        self.buf.put_u32(n);
    }

    pub fn put_u64(&mut self, n: u64) {
        self.buf.put_u64(n);
    }

    pub fn put_f32(&mut self, n: f32) {
        self.buf.put_f32(n);
    }

    pub fn put_f64(&mut self, n: f64) {
        self.buf.put_f64(n);
    }

    pub fn put_i8(&mut self, n: i8) {
        self.buf.put_i8(n);
    }

    pub fn put_i16(&mut self, n: i16) {
        self.buf.put_i16(n);
    }

    pub fn put_i32(&mut self, n: i32) {
        self.buf.put_i32(n);
    }

    pub fn put_i64(&mut self, n: i64) {
        self.buf.put_i64(n);
    }

    // متدهای اضافی

    // اضافه کردن داده از یک slice
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    // اضافه کردن داده از یک Bytes
    pub fn extend_from_bytes(&mut self, data: Bytes) {
        self.buf.extend_from_slice(data.as_ref());
    }

    // اضافه کردن داده از یک Vec<u8>
    pub fn extend_from_vec(&mut self, data: Vec<u8>) {
        self.buf.extend(data);
    }

    // پاک کردن تمام داده‌ها از بافر
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    // تقسیم بافر به دو قسمت
    pub fn split(&mut self) -> BytesMut {
        self.buf.split()
    }

    // کوتاه کردن بافر به اندازه دلخواه
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    // گرفتن یک بخش از بافر
    pub fn take(&mut self, len: usize) -> io::Result<BytesMut> {
        if self.buf.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Buffer is too short to take {} bytes", len),
            ));
        }
        Ok(self.buf.split_to(len))
    }

    // تبدیل بافر به Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.buf.to_vec()
    }

    // متدهای قبلی که قبلاً اضافه کردیم...

    pub fn advance(&mut self, cnt: usize) -> io::Result<()> {
        if cnt > self.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Cannot advance by {}: Not enough data in buffer", cnt),
            ));
        }
        self.buf.advance(cnt);
        Ok(())
    }

    pub fn reserve(&mut self, additional: usize) {
        self.buf.reserve(additional);
    }

    pub fn remaining_mut(&self) -> usize {
        self.buf.remaining_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn get_u16(&mut self) -> io::Result<u16> {
        if self.buf.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is too short to extract u16",
            ));
        }
        Ok(self.buf.get_u16())
    }

    pub fn get_u32(&mut self) -> io::Result<u32> {
        if self.buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is too short to extract u32",
            ));
        }
        Ok(self.buf.get_u32())
    }

    pub fn get_u64(&mut self) -> io::Result<u64> {
        if self.buf.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is too short to extract u64",
            ));
        }
        Ok(self.buf.get_u64())
    }

    pub fn get_u128(&mut self) -> io::Result<u128> {
        if self.buf.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is too short to extract u128",
            ));
        }
        Ok(self.buf.get_u128())
    }

    pub fn split_to(&mut self, len: usize) -> io::Result<BytesMut> {
        if self.buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is empty",
            ));
        }
        if self.buf.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Buffer is too short to split. Needed: {}, but have: {}",
                    len,
                    self.buf.len()
                ),
            ));
        }
        Ok(self.buf.split_to(len))
    }

    pub fn split_off(&mut self, len: usize) -> io::Result<BytesMut> {
        if self.buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is empty",
            ));
        }
        if self.buf.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Buffer is too short to split. Needed: {}, but have: {}",
                    len,
                    self.buf.len()
                ),
            ));
        }
        Ok(self.buf.split_off(len))
    }

    pub fn get_f32(&mut self) -> io::Result<f32> {
        if self.buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is too short to extract f32",
            ));
        }
        Ok(self.buf.get_f32())
    }

    pub fn get_f64(&mut self) -> io::Result<f64> {
        if self.buf.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer is too short to extract f64",
            ));
        }
        Ok(self.buf.get_f64())
    }

    pub fn get_utf8(&mut self, len: usize) -> io::Result<String> {
        if self.buf.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Buffer is too short to extract {} bytes for UTF-8 string",
                    len
                ),
            ));
        }
        let data = self.buf.split_to(len);
        match String::from_utf8(data.to_vec()) {
            Ok(s) => Ok(s),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to convert to UTF-8",
            )),
        }
    }

    pub fn to_cursor(&self) -> Cursor<&[u8]> {
        Cursor::new(&self.buf)
    }
}
