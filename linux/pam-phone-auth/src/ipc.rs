//! The PAM module uses the daemon's control client directly.
//!
//! It is re-exported here rather than reimplemented so that PAM and any other
//! integration speak the protocol through exactly one piece of code.

pub use phone_authd::ipc::{
    call, default_socket, ClientRequest as Request, ClientResponse as Response, IpcError,
};
