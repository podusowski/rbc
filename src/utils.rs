use std::io::Write;

pub(crate) fn write_padded_bytes(sink: &mut impl Write, buf: &[u8], total_length: usize) {
    sink.write_all(buf).unwrap();
    assert!(
        buf.len() <= total_length,
        "resulting write would be bigger than `total_length`"
    );
    for _ in 0..total_length - buf.len() {
        sink.write(&[0]).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smaller_data_gets_additional_padding() {
        let mut sink = Vec::new();
        write_padded_bytes(&mut sink, &[1], 2);
        assert_eq!(vec![1, 0], sink);
    }

    #[test]
    #[should_panic = "resulting write would be bigger than `total_length`"]
    fn panic_when_data_does_not_fit() {
        let mut sink = Vec::new();
        write_padded_bytes(&mut sink, &[1, 2, 3], 2);
        assert_eq!(vec![1, 0], sink);
    }
}
