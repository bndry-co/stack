//! Test inputs as a binding sends them: an [`FfiValue`] written as frame
//! bytes, objects and arrays by hand so a test can send a repeated key,
//! which no frame writer would.

use vitaminc_protected::Controlled;

use super::FfiValue;

/// What a binding reads back from an answer the engine writes: its frame,
/// decoded.
pub(crate) fn value_of<T: serde::Serialize>(answer: &T) -> FfiValue {
    let frame = vitaminc_aead_frame::serde::to_vec(answer).expect("frames");
    FfiValue::from_frame(&frame).expect("a value")
}

/// The frame bytes of `value`.
pub(crate) fn frame_of(value: &FfiValue) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn write(value: &FfiValue, out: &mut Vec<u8>) {
    let count = |len: usize| u32::try_from(len).expect("short").to_le_bytes();
    match value {
        FfiValue::Object(entries) => {
            out.push(vitaminc_aead::frame::OBJECT);
            out.extend_from_slice(&count(entries.len()));
            for (key, value) in entries {
                out.extend_from_slice(&count(key.len()));
                out.extend_from_slice(key.as_bytes());
                write(value, out);
            }
        }
        FfiValue::Array(items) => {
            out.push(vitaminc_aead::frame::ARRAY);
            out.extend_from_slice(&count(items.len()));
            for item in items {
                write(item, out);
            }
        }
        other => out.extend_from_slice(other.to_frame().expect("frames").risky_ref()),
    }
}
