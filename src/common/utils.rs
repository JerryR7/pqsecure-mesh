use anyhow::Result;
use std::path::Path;
use std::fs;
use tracing::trace;

/// Read a file as bytes, useful for loading certificates and keys
pub fn read_file_bytes<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let path = path.as_ref();
    trace!("Reading file: {}", path.display());
    Ok(fs::read(path)?)
}

/// Read a file as string, useful for loading config files
pub fn read_file_string<P: AsRef<Path>>(path: P) -> Result<String> {
    let path = path.as_ref();
    trace!("Reading file as string: {}", path.display());
    Ok(fs::read_to_string(path)?)
}

/// Write bytes to a file with proper permissions, useful for saving certificates
pub fn write_file_bytes<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    let path = path.as_ref();
    trace!("Writing {} bytes to file: {}", data.len(), path.display());

    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    // Write the file with restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(path)?;
        std::io::Write::write_all(&mut file, data)?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }

    Ok(())
}

/// Check if a file exists and is readable
pub fn file_exists_and_readable<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();
    path.exists() && path.is_file()
}