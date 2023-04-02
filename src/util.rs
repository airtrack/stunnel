use async_std::fs::{remove_file, rename, File, OpenOptions};
use async_std::io::WriteExt;

pub struct FileRotate {
    path: String,
    file: Option<File>,
    header: Option<Vec<u8>>,
    rotate_size: usize,
    rotate_count: usize,
    written_size: usize,
}

impl FileRotate {
    pub async fn open(
        path: String,
        rotate_size: usize,
        rotate_count: usize,
        header: Option<Vec<u8>>,
    ) -> Self {
        let mut file_rotate = Self {
            path,
            file: None,
            header,
            rotate_size,
            rotate_count,
            written_size: 0,
        };

        file_rotate.open_file().await;
        file_rotate
    }

    pub async fn write_all(&mut self, buf: &[u8]) {
        if let Some(ref mut f) = self.file {
            let _ = f.write_all(buf).await;
            // Call async_std::fs::File::flush to drain buffer in async_std::fs::File,
            // which means call std::fs::File::write_all.
            let _ = f.flush().await;
        }

        self.written_size += buf.len();
        if self.written_size >= self.rotate_size {
            self.rotate_file().await;
        }
    }

    async fn rotate_file(&mut self) {
        if self.rotate_count == 0 {
            return;
        }

        let mut file_number = self.rotate_count - 1;
        let _ = remove_file(self.generate_rotate_file_name(file_number)).await;

        while file_number > 0 {
            let to = self.generate_rotate_file_name(file_number);
            let from = self.generate_rotate_file_name(file_number - 1);
            let _ = rename(from, to).await;
            file_number -= 1;
        }

        self.open_file().await;
    }

    async fn open_file(&mut self) {
        self.written_size = 0;
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)
            .await
            .ok();

        if let Some(ref file) = self.file {
            match file.metadata().await {
                Ok(metadata) => {
                    self.written_size = metadata.len() as usize;
                }
                Err(_) => {}
            }
        }

        self.write_file_header().await;
    }

    async fn write_file_header(&mut self) {
        if self.header.is_none() {
            return;
        }

        if let Some(ref mut file) = self.file {
            if self.written_size == 0 {
                let header = self.header.as_ref().unwrap();
                let _ = file.write_all(header).await;
                self.written_size += header.len();
            }
        }
    }

    fn generate_rotate_file_name(&self, file_number: usize) -> String {
        let mut path = self.path.clone();

        if file_number > 0 {
            path.push('.');
            path.push_str(&file_number.to_string());
        }

        path
    }
}
