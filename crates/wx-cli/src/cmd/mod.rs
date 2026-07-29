pub mod contacts;
pub mod db_dev;
pub mod decode_image;
pub mod decrypt;
pub mod doctor;
pub mod export;
pub mod export_media;
pub mod export_task;
pub mod info;
pub mod key;
pub mod media;
pub mod paths;
pub mod query;
pub mod search;
pub mod serve;
pub mod server;
pub mod sessions;
pub mod status;
pub mod thin_client;
pub mod watch;

#[cfg(test)]
mod thin_client_tests;
