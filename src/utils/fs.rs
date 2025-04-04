use std::path::{Path, PathBuf};
use tokio::fs;

use crate::error::Error;

/// File system utilities
pub struct FsUtils;

impl FsUtils {
    /// Ensure the directory exists
    pub async fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            fs::create_dir_all(path).await
                .map_err(|e| Error::Io(e))?;
        }
        
        Ok(())
    }
    
    /// Write to a file (create the directory if it does not exist)
    pub async fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<(), Error> {
        let path = path.as_ref();
        
        // Ensure the parent directory exists
        if let Some(parent) = path.parent() {
            Self::ensure_dir_exists(parent).await?;
        }
        
        // Write to the file
        fs::write(path, contents).await
            .map_err(|e| Error::Io(e))?;
        
        Ok(())
    }
    
    /// Read file contents
    pub async fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(Error::NotFound(format!("File not found: {:?}", path)));
        }
        
        fs::read(path).await
            .map_err(|e| Error::Io(e))
    }
    
    /// Read file as a string
    pub async fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String, Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(Error::NotFound(format!("File not found: {:?}", path)));
        }
        
        fs::read_to_string(path).await
            .map_err(|e| Error::Io(e))
    }
    
    /// Check if a file exists
    pub async fn exists<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().exists()
    }
    
    /// Delete a file
    pub async fn remove_file<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Ok(());
        }
        
        fs::remove_file(path).await
            .map_err(|e| Error::Io(e))
    }
    
    /// Delete a directory
    pub async fn remove_dir<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Ok(());
        }
        
        fs::remove_dir(path).await
            .map_err(|e| Error::Io(e))
    }
    
    /// Delete a directory and all its contents
    pub async fn remove_dir_all<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Ok(());
        }
        
        fs::remove_dir_all(path).await
            .map_err(|e| Error::Io(e))
    }
    
    /// List files in a directory
    pub async fn list_dir<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>, Error> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(Error::NotFound(format!("Directory not found: {:?}", path)));
        }
        
        if !path.is_dir() {
            return Err(Error::InvalidRequest(format!("Not a directory: {:?}", path)));
        }
        
        let mut entries = fs::read_dir(path).await
            .map_err(|e| Error::Io(e))?;
        
        let mut paths = Vec::new();
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| Error::Io(e))? {
            
            paths.push(entry.path());
        }
        
        Ok(paths)
    }
    
    /// Copy a file
    pub async fn copy_file<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<u64, Error> {
        let from = from.as_ref();
        let to = to.as_ref();
        
        if !from.exists() {
            return Err(Error::NotFound(format!("Source file not found: {:?}", from)));
        }
        
        // Ensure the target directory exists
        if let Some(parent) = to.parent() {
            Self::ensure_dir_exists(parent).await?;
        }
        
        fs::copy(from, to).await
            .map_err(|e| Error::Io(e))
    }
    
    /// Move a file
    pub async fn move_file<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<(), Error> {
        let from = from.as_ref();
        let to = to.as_ref();
        
        if !from.exists() {
            return Err(Error::NotFound(format!("Source file not found: {:?}", from)));
        }
        
        // Ensure the target directory exists
        if let Some(parent) = to.parent() {
            Self::ensure_dir_exists(parent).await?;
        }
        
        fs::rename(from, to).await
            .map_err(|e| Error::Io(e))
    }
}