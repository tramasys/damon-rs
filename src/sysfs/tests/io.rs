use super::*;

#[test]
fn numeric_reader_rejects_oversized_input() {
    let fixture = TempFile::new(&"9".repeat(65));
    assert!(read_u64(&fixture.path).is_err());
}

#[test]
fn numeric_reader_accepts_kernel_whitespace() {
    let fixture = TempFile::new("  18446744073709551615\n");
    assert_eq!(read_u64(&fixture.path).expect("read u64::MAX"), u64::MAX);
}

#[test]
fn numeric_reader_reports_malformed_values() {
    let fixture = TempFile::new("not-a-number\n");
    let error = read_u64(&fixture.path).expect_err("reject malformed value");

    assert!(matches!(
        error,
        Error::InvalidKernelValue {
            value,
            expected: "u64",
            ..
        } if &*value == "not-a-number"
    ));
}

#[test]
fn bool_reader_accepts_values_emitted_and_accepted_by_linux() {
    for (value, expected) in [("Y\n", true), ("N\n", false), ("1\n", true), ("0\n", false)] {
        let fixture = TempFile::new(value);
        assert_eq!(read_bool(&fixture.path).expect("read boolean"), expected);
    }
}

#[test]
fn fingerprint_comparison_streams_long_values_without_losing_spaces() {
    let expected = format!("  {}  ", "x".repeat(600));
    let fixture = TempFile::new(&format!("{expected}\n"));

    assert!(
        read_configuration_value_equals(&fixture.path, expected.as_bytes())
            .expect("compare long unchanged value")
    );
    assert!(
        !read_configuration_value_equals(&fixture.path, expected.trim().as_bytes())
            .expect("preserve surrounding spaces")
    );
    assert!(
        !read_configuration_value_equals(&fixture.path, b"different")
            .expect("detect changed value")
    );
}

#[test]
fn kernel_ulong_max_falls_back_after_kernel_range_error() {
    let mut attempted = Vec::new();
    let selected = select_kernel_ulong_max(|value| {
        attempted.push(value);
        if value == u64::MAX {
            return Err(io_error("write", "max", io::Error::from_raw_os_error(34)));
        }
        Ok(())
    })
    .expect("fall back to 32-bit kernel maximum");

    assert_eq!(selected, u64::from(u32::MAX));
    assert_eq!(attempted, [u64::MAX, u64::from(u32::MAX)]);
}

#[test]
fn sysfs_write_is_submitted_in_one_call() {
    let mut writer = RecordingWriter::default();
    write_once(&mut writer, Path::new("state"), b"on").expect("write complete value");

    assert_eq!(writer.calls, 1);
    assert_eq!(writer.bytes, b"on");
}

#[test]
fn sysfs_write_retries_interruption_before_submitting_bytes() {
    let mut writer = InterruptedWriter::default();
    write_once(&mut writer, Path::new("state"), b"off").expect("retry interruption");

    assert_eq!(writer.calls, 2);
    assert_eq!(writer.bytes, b"off");
}

#[test]
fn sysfs_write_rejects_a_short_first_write() {
    let error = write_once(&mut ShortWriter, Path::new("state"), b"commit")
        .expect_err("short sysfs write must fail");

    assert!(matches!(
        error,
        Error::Io {
            operation: "write complete value",
            source,
            ..
        } if source.kind() == io::ErrorKind::WriteZero
    ));
}
