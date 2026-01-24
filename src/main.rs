//! eBPF plugin for Nushell
//!
//! This plugin compiles Nushell closures to eBPF bytecode and attaches them to
//! kernel probe points for high-performance tracing.

use nu_plugin::{MsgPackSerializer, serve_plugin};
use nu_plugin_ebpf::EbpfPlugin;

fn main() {
    serve_plugin(&EbpfPlugin, MsgPackSerializer);
}
