#![allow(unused_imports)]

#[cfg(not(any(feature = "runtime-tokio", feature = "runtime-async-std")))]
compile_error!("one of 'runtime-async-std' or 'runtime-tokio' features must be enabled");

#[cfg(all(feature = "runtime-tokio", feature = "runtime-async-std"))]
compile_error!("only one of 'runtime-async-std' or 'runtime-tokio' features must be enabled");

#[cfg(all(feature = "runtime-async-std", target_arch = "wasm32"))]
pub(crate) use async_std::task::spawn_local as spawn;
#[cfg(all(feature = "runtime-async-std", not(target_arch = "wasm32")))]
pub(crate) use async_std::{fs::File, path::Path, task::spawn};
#[cfg(feature = "runtime-async-std")]
pub(crate) use async_std::{
    io::{
        prelude::{
            BufReadExt as AsyncBufReadExt, ReadExt as AsyncReadExt, WriteExt as AsyncWriteExt,
        },
        BufReader, Cursor, Error, ErrorKind,
    },
    stream::StreamExt,
    sync::{channel, Receiver},
};

#[cfg(feature = "runtime-tokio")]
pub(crate) use std::io::Cursor;
#[cfg(all(feature = "runtime-tokio", not(target_arch = "wasm32")))]
pub(crate) use std::path::Path;
#[cfg(all(feature = "runtime-tokio", not(target_arch = "wasm32")))]
pub(crate) use tokio::fs::File;
#[cfg(feature = "runtime-tokio")]
pub(crate) use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Error, ErrorKind},
    stream::StreamExt,
    sync::mpsc::{channel, error::SendError, Receiver},
    task::spawn,
};
