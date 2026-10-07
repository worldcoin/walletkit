//! Binary encoding for records, enumerations, lists, maps, and errors.
//!
//! Each type has exactly one Rust encoder or decoder; Kotlin and Swift implement the
//! matching decoders (results) and encoders (inputs). The layout is:
//!
//! ```text
//! u8 u16 u32 u64     little-endian unsigned integers
//! bool               u8, 0 or 1
//! f32 f64            IEEE 754 bits as u32 / u64
//! str, bytes         length:u32, then UTF-8 or raw bytes
//! Uint256            32 big-endian bytes, no length prefix
//! handle             u64 registry ID; the receiver owns it
//! Option<T>          u8 tag (0 = absent, 1 = present), then T
//! Vec<T>             count:u32, then each T
//! Map<K, V>          count:u32, then each K, V
//! fieldless enum     u8 ordinal, as listed in `values.rs`
//! enum with fields   u8 variant index, then the variant's fields in declaration order
//! record             fields in declaration order
//! ```
//!
//! Decoders reject short input, trailing bytes, unknown tags, and invalid UTF-8.

use super::{
    error::{NativeError, Result},
    registry::{self, NativeObject},
};
use std::{collections::HashMap, hash::Hash, sync::Arc};
use walletkit_core::Uint256;

/// A value written in the binary encoding.
pub trait Encode {
    /// Appends `self` to `writer`.
    fn encode(self, writer: &mut Writer) -> Result<()>;
}

/// A value read from the binary encoding.
pub trait Decode: Sized {
    /// Reads one value from `reader`.
    fn decode(reader: &mut Reader<'_>) -> Result<Self>;
}

/// A value crossing the boundary in the binary encoding instead of as primitives.
pub struct Binary<T>(pub T);

/// Encodes a complete value. Handles written into it are released unless claimed.
pub fn encode<T: Encode>(value: T) -> Result<Encoded> {
    let mut writer = Writer::default();
    value.encode(&mut writer)?;
    Ok(writer.finish())
}

/// Decodes a complete value, rejecting trailing bytes.
pub fn decode<T: Decode>(bytes: &[u8]) -> Result<T> {
    let mut reader = Reader { bytes };
    let value = T::decode(&mut reader)?;
    if reader.bytes.is_empty() {
        Ok(value)
    } else {
        Err(NativeError::invalid_input())
    }
}

/// Encoded bytes plus the handles they transfer. Dropping it releases the handles, so a
/// result that never reaches the host leaks no resources.
pub struct Encoded {
    bytes: Vec<u8>,
    handles: Vec<u64>,
}

impl Encoded {
    /// The encoded bytes.
    #[cfg(any(feature = "jni", test))]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfers the handles to the host, which now owns them.
    pub fn claim(mut self) -> Vec<u8> {
        self.handles.clear();
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for Encoded {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
            registry::release(handle);
        }
    }
}

/// Appends values in the binary encoding. Handles written into an unfinished value are
/// released when the writer is dropped, for example when a later field fails to encode.
#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
    handles: Vec<u64>,
}

impl Drop for Writer {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
            registry::release(handle);
        }
    }
}

impl Writer {
    fn finish(mut self) -> Encoded {
        Encoded {
            bytes: std::mem::take(&mut self.bytes),
            handles: std::mem::take(&mut self.handles),
        }
    }

    /// Returns the bytes of a value that contains no handles, such as an error.
    pub fn into_bytes(self) -> Vec<u8> {
        debug_assert!(self.handles.is_empty());
        self.finish().claim()
    }

    /// Writes a `u8`.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Writes a little-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a boolean as 0 or 1.
    pub fn bool(&mut self, value: bool) {
        self.u8(value.into());
    }

    /// Writes a length or count.
    pub fn length(&mut self, length: usize) -> Result<()> {
        self.u32(
            u32::try_from(length).map_err(|_| NativeError::bridge("ValueTooLarge"))?,
        );
        Ok(())
    }

    /// Writes length-prefixed bytes.
    pub fn bytes(&mut self, value: &[u8]) -> Result<()> {
        self.length(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Writes a length-prefixed UTF-8 string.
    pub fn string(&mut self, value: &str) -> Result<()> {
        self.bytes(value.as_bytes())
    }

    /// Registers `object` and writes its handle; the handle is released if the encoded
    /// value is dropped before the host claims it.
    pub fn handle<T: NativeObject + ?Sized>(&mut self, object: Arc<T>) -> Result<()> {
        let id = registry::insert(object)?;
        self.handles.push(id);
        self.u64(id);
        Ok(())
    }
}

/// Reads values in the binary encoding.
pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if count > self.bytes.len() {
            return Err(NativeError::invalid_input());
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("took exactly N bytes"))
    }

    /// Reads a `u8`.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_le_bytes)
    }

    /// Reads a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// Reads a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }

    /// Reads a boolean, rejecting values other than 0 and 1.
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(NativeError::invalid_input()),
        }
    }

    /// Reads a length or count that must fit in the remaining input.
    pub fn length(&mut self) -> Result<usize> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| NativeError::invalid_input())?;
        if length > self.bytes.len() {
            return Err(NativeError::invalid_input());
        }
        Ok(length)
    }

    /// Reads length-prefixed bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = self.length()?;
        self.take(length)
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn string(&mut self) -> Result<String> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| NativeError::invalid_input())
    }

    /// Reads an enumeration ordinal or variant index.
    pub fn tag(&mut self) -> Result<u8> {
        self.u8()
    }
}

macro_rules! integer {
    ($($ty:ident),*) => {$(
        impl Encode for $ty {
            fn encode(self, writer: &mut Writer) -> Result<()> {
                writer.$ty(self);
                Ok(())
            }
        }
        impl Decode for $ty {
            fn decode(reader: &mut Reader<'_>) -> Result<Self> {
                reader.$ty()
            }
        }
    )*};
}
integer!(u16, u32, u64, bool);

impl Encode for f32 {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.u32(self.to_bits());
        Ok(())
    }
}

impl Encode for f64 {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.u64(self.to_bits());
        Ok(())
    }
}

impl Decode for f64 {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        reader.u64().map(Self::from_bits)
    }
}

impl Encode for String {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.string(&self)
    }
}

impl Decode for String {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        reader.string()
    }
}

impl Encode for Vec<u8> {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.bytes(&self)
    }
}

impl Decode for Vec<u8> {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        reader.bytes().map(<[u8]>::to_vec)
    }
}

impl Encode for Uint256 {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.bytes.extend_from_slice(&self.0.to_be_bytes::<32>());
        Ok(())
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            None => {
                writer.u8(0);
                Ok(())
            }
            Some(value) => {
                writer.u8(1);
                value.encode(writer)
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.u8()? {
            0 => Ok(None),
            1 => T::decode(reader).map(Some),
            _ => Err(NativeError::invalid_input()),
        }
    }
}

/// Lists of any encodable element except bytes, which use the length-prefixed form.
pub trait Element {}
impl Element for String {}
impl Element for u64 {}
impl<T> Element for Option<T> {}
impl<T: NativeObject + ?Sized> Element for Arc<T> {}

impl<T: Encode + Element> Encode for Vec<T> {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.length(self.len())?;
        self.into_iter().try_for_each(|value| value.encode(writer))
    }
}

/// Upper bound on elements reserved before decoding, so that a count prefix cannot
/// reserve much more memory than the input it came with.
const MAX_RESERVED: usize = 1024;

impl<T: Decode + Element> Decode for Vec<T> {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let count = reader.length()?;
        let mut values = Self::with_capacity(count.min(MAX_RESERVED));
        for _ in 0..count {
            values.push(T::decode(reader)?);
        }
        Ok(values)
    }
}

impl<K: Encode, V: Encode> Encode for HashMap<K, V> {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.length(self.len())?;
        self.into_iter().try_for_each(|(key, value)| {
            key.encode(writer)?;
            value.encode(writer)
        })
    }
}

impl<K: Decode + Eq + Hash, V: Decode> Decode for HashMap<K, V> {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let count = reader.length()?;
        let mut map = Self::with_capacity(count.min(MAX_RESERVED));
        for _ in 0..count {
            let key = K::decode(reader)?;
            if map.insert(key, V::decode(reader)?).is_some() {
                return Err(NativeError::invalid_input());
            }
        }
        Ok(map)
    }
}

impl<T: NativeObject + ?Sized> Encode for Arc<T> {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.handle(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walletkit_core::FieldElement;

    #[test]
    fn dropped_encoded_results_release_their_handles() {
        let encoded = encode(vec![Arc::new(FieldElement::from_u64(1))]).unwrap();
        let id = u64::from_le_bytes(encoded.bytes()[4..12].try_into().unwrap());
        assert!(registry::get::<FieldElement>(id).is_ok());
        drop(encoded);
        assert!(registry::get::<FieldElement>(id).is_err());

        let claimed = encode(vec![Arc::new(FieldElement::from_u64(2))]).unwrap();
        let id = u64::from_le_bytes(claimed.claim()[4..12].try_into().unwrap());
        assert!(registry::get::<FieldElement>(id).is_ok());
        registry::release(id);
    }

    #[test]
    fn handles_from_a_failed_encoding_are_released() {
        struct HandleThenFail(Arc<FieldElement>);
        impl Encode for HandleThenFail {
            fn encode(self, writer: &mut Writer) -> Result<()> {
                writer.handle(self.0)?;
                Err(NativeError::bridge("ValueTooLarge"))
            }
        }
        let field = Arc::new(FieldElement::from_u64(3));
        let weak = Arc::downgrade(&field);
        assert!(encode(HandleThenFail(field)).is_err());
        assert!(
            weak.upgrade().is_none(),
            "the registered handle was released"
        );
    }
}
