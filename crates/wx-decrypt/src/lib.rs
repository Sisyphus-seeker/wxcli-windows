pub mod db;
pub mod dispatch;
pub mod error;
mod file_io;
pub mod kdf;
pub mod key_material;
pub mod page;
pub mod params;
pub mod wal;

pub use db::{
    decrypt_db, decrypt_db_direct, read_db_salt, read_main_db_salt_for_path, validate_enc_key,
    validate_enc_key_header, validate_enc_key_header_reserves, validate_key,
};
pub use dispatch::{dispatch_decrypt_db, dispatch_decrypt_wal};
pub use error::DecryptError;
pub use file_io::read_prefix_shared;
pub use key_material::{EncKeyPair, KeyMaterial};
pub use params::{platform_default_params, CryptoParams, MACOS_4_1_7_31, WINDOWS_4_1_X};
pub use wal::{decrypt_wal, decrypt_wal_direct};
