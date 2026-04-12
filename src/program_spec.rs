use crate::compiler::EbpfProgramType;
use aya::programs::{
    CgroupSkbAttachType, CgroupSockAddrAttachType, CgroupSockAttachType, CgroupSockoptAttachType,
    TcAttachType,
};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramSpecParseError {
    message: String,
}

impl ProgramSpecParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProgramSpecParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProgramSpecParseError {}

/// Parsed uprobe/uretprobe target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UprobeTarget {
    /// Path to the binary or library.
    pub binary_path: String,
    /// Function name (None if using offset-only).
    pub function_name: Option<String>,
    /// Offset within the function or binary (0 if attaching to function entry).
    pub offset: u64,
    /// Optional PID to filter (None means all processes).
    pub pid: Option<i32>,
}

impl UprobeTarget {
    /// Parse a uprobe target string.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (target_part, pid) = if let Some(at_idx) = target.rfind('@') {
            let pid_str = &target[at_idx + 1..];
            match pid_str.parse::<i32>() {
                Ok(pid) => (&target[..at_idx], Some(pid)),
                Err(_) => (target, None),
            }
        } else {
            (target, None)
        };

        let colon_idx = target_part.rfind(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid uprobe target: {target}. Expected format: /path/to/binary:function_name"
            ))
        })?;

        let binary_path = target_part[..colon_idx].to_string();
        let func_or_offset = &target_part[colon_idx + 1..];

        if binary_path.is_empty() {
            return Err(ProgramSpecParseError::new(
                "Uprobe binary path cannot be empty",
            ));
        }

        let (function_name, offset) = if let Some(plus_idx) = func_or_offset.find('+') {
            let name = &func_or_offset[..plus_idx];
            let offset_str = &func_or_offset[plus_idx + 1..];
            let offset = parse_offset(offset_str)?;
            (Some(name.to_string()), offset)
        } else if func_or_offset.starts_with("0x") || func_or_offset.starts_with("0X") {
            (None, parse_offset(func_or_offset)?)
        } else {
            (Some(func_or_offset.to_string()), 0)
        };

        Ok(Self {
            binary_path,
            function_name,
            offset,
            pid,
        })
    }

    /// Render this parsed target back into canonical target syntax.
    pub fn target_string(&self) -> String {
        let mut target = String::with_capacity(self.binary_path.len() + 32);
        target.push_str(&self.binary_path);
        target.push(':');
        match (&self.function_name, self.offset) {
            (Some(function_name), 0) => target.push_str(function_name),
            (Some(function_name), offset) => {
                target.push_str(function_name);
                target.push('+');
                target.push_str(&format!("0x{offset:x}"));
            }
            (None, offset) => target.push_str(&format!("0x{offset:x}")),
        }
        if let Some(pid) = self.pid {
            target.push('@');
            target.push_str(&pid.to_string());
        }
        target
    }
}

fn parse_offset(s: &str) -> Result<u64, ProgramSpecParseError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|_| ProgramSpecParseError::new(format!("Invalid hex offset: {s}")))
    } else {
        s.parse::<u64>()
            .map_err(|_| ProgramSpecParseError::new(format!("Invalid offset: {s}")))
    }
}

/// Parsed tc target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcTarget {
    /// Network interface name.
    pub interface: String,
    /// Attach direction.
    pub attach_type: TcAttachType,
}

impl TcTarget {
    /// Parse a tc target string of the form `iface:ingress` or `iface:egress`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (interface, direction) = target.split_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid tc target: {target}. Expected format: interface:ingress or interface:egress"
            ))
        })?;

        if interface.is_empty() {
            return Err(ProgramSpecParseError::new(
                "TC interface target cannot be empty",
            ));
        }

        let attach_type = match direction {
            "ingress" => TcAttachType::Ingress,
            "egress" => TcAttachType::Egress,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid tc attach direction: {direction}. Expected ingress or egress"
                )));
            }
        };

        Ok(Self {
            interface: interface.to_string(),
            attach_type,
        })
    }

    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            TcAttachType::Ingress => "ingress",
            TcAttachType::Egress => "egress",
            _ => "unknown",
        }
    }

    pub fn is_ingress(&self) -> bool {
        matches!(self.attach_type, TcAttachType::Ingress)
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.interface, self.attach_type_name())
    }
}

/// Parsed cgroup_skb target information.
#[derive(Debug, Clone)]
pub struct CgroupSkbTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
    /// Attach direction.
    pub attach_type: CgroupSkbAttachType,
}

impl CgroupSkbTarget {
    /// Parse a cgroup_skb target string of the form `/sys/fs/cgroup:ingress`
    /// or `/sys/fs/cgroup:egress`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (cgroup_path, direction) = target.rsplit_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid cgroup_skb target: {target}. Expected format: /path/to/cgroup:ingress or /path/to/cgroup:egress"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(ProgramSpecParseError::new(
                "cgroup_skb cgroup path cannot be empty",
            ));
        }

        let attach_type = match direction {
            "ingress" => CgroupSkbAttachType::Ingress,
            "egress" => CgroupSkbAttachType::Egress,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid cgroup_skb attach direction: {direction}. Expected ingress or egress"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }

    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSkbAttachType::Ingress => "ingress",
            CgroupSkbAttachType::Egress => "egress",
        }
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }

    pub fn section_name(&self) -> String {
        format!("cgroup_skb/{}", self.attach_type_name())
    }
}

impl PartialEq for CgroupSkbTarget {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_path == other.cgroup_path && self.attach_type_name() == other.attach_type_name()
    }
}

impl Eq for CgroupSkbTarget {}

/// Parsed cgroup_sock target information.
#[derive(Debug, Clone)]
pub struct CgroupSockTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
    /// Attach kind.
    pub attach_type: CgroupSockAttachType,
}

impl CgroupSockTarget {
    /// Parse a cgroup_sock target string of the form `/sys/fs/cgroup:sock_create`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (cgroup_path, attach_kind) = target.rsplit_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid cgroup_sock target: {target}. Expected format: /path/to/cgroup:sock_create|sock_release|post_bind4|post_bind6"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(ProgramSpecParseError::new(
                "cgroup_sock cgroup path cannot be empty",
            ));
        }

        let attach_type = match attach_kind {
            "sock_create" => CgroupSockAttachType::SockCreate,
            "sock_release" => CgroupSockAttachType::SockRelease,
            "post_bind4" => CgroupSockAttachType::PostBind4,
            "post_bind6" => CgroupSockAttachType::PostBind6,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid cgroup_sock attach kind: {attach_kind}. Expected sock_create, sock_release, post_bind4, or post_bind6"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }

    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSockAttachType::PostBind4 => "post_bind4",
            CgroupSockAttachType::PostBind6 => "post_bind6",
            CgroupSockAttachType::SockCreate => "sock_create",
            CgroupSockAttachType::SockRelease => "sock_release",
        }
    }

    pub fn is_post_bind(&self) -> bool {
        matches!(
            self.attach_type,
            CgroupSockAttachType::PostBind4 | CgroupSockAttachType::PostBind6
        )
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }

    pub fn section_name(&self) -> String {
        format!("cgroup/{}", self.attach_type_name())
    }
}

impl PartialEq for CgroupSockTarget {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_path == other.cgroup_path && self.attach_type_name() == other.attach_type_name()
    }
}

impl Eq for CgroupSockTarget {}

/// Parsed cgroup_device target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupDeviceTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
}

impl CgroupDeviceTarget {
    /// Parse a cgroup_device target string of the form `/sys/fs/cgroup`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "cgroup_device cgroup path cannot be empty",
            ));
        }

        Ok(Self {
            cgroup_path: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.cgroup_path.clone()
    }

    pub fn section_name(&self) -> &'static str {
        "cgroup/dev"
    }
}

/// Parsed sock_ops target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockOpsTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
}

impl SockOpsTarget {
    /// Parse a sock_ops target string of the form `/sys/fs/cgroup`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "sock_ops cgroup path cannot be empty",
            ));
        }

        Ok(Self {
            cgroup_path: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.cgroup_path.clone()
    }
}

/// Parsed sk_msg target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkMsgTarget {
    /// Filesystem path to a pinned sockmap or sockhash map.
    pub map_path: String,
}

impl SkMsgTarget {
    /// Parse an sk_msg target string of the form `/sys/fs/bpf/pinned_sockmap`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "sk_msg pinned sockmap path cannot be empty",
            ));
        }

        Ok(Self {
            map_path: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.map_path.clone()
    }
}

/// Parsed sk_skb target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkSkbTarget {
    /// Filesystem path to a pinned sockmap or sockhash map.
    pub map_path: String,
}

impl SkSkbTarget {
    /// Parse an sk_skb target string of the form `/sys/fs/bpf/pinned_sockmap`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "sk_skb pinned sockmap path cannot be empty",
            ));
        }

        Ok(Self {
            map_path: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.map_path.clone()
    }
}

/// Supported socket kinds for the initial socket_filter surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketFilterSocketKind {
    Udp4,
    Udp6,
    Tcp4,
    Tcp6,
}

impl SocketFilterSocketKind {
    pub fn name(&self) -> &'static str {
        match self {
            SocketFilterSocketKind::Udp4 => "udp4",
            SocketFilterSocketKind::Udp6 => "udp6",
            SocketFilterSocketKind::Tcp4 => "tcp4",
            SocketFilterSocketKind::Tcp6 => "tcp6",
        }
    }
}

/// Parsed socket_filter target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketFilterTarget {
    /// Bound socket kind.
    pub socket_kind: SocketFilterSocketKind,
    /// Local IPv4 bind address.
    pub bind_ip: String,
    /// Local UDP port.
    pub bind_port: u16,
}

impl SocketFilterTarget {
    /// Parse a socket_filter target string of the form `udp4:127.0.0.1:31337`,
    /// `udp6:[::1]:31337`, `tcp4:127.0.0.1:31337`, or `tcp6:[::1]:31337`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        const EXPECTED: &str = "udp4:IP:PORT, udp6:[IPV6]:PORT, tcp4:IP:PORT, or tcp6:[IPV6]:PORT";
        let (socket_kind, rest) = target.split_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid socket_filter target: {target}. Expected format: {EXPECTED}"
            ))
        })?;
        let (bind_ip, bind_port) = rest.rsplit_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid socket_filter target: {target}. Expected format: {EXPECTED}"
            ))
        })?;

        let socket_kind = match socket_kind {
            "udp4" => SocketFilterSocketKind::Udp4,
            "udp6" => SocketFilterSocketKind::Udp6,
            "tcp4" => SocketFilterSocketKind::Tcp4,
            "tcp6" => SocketFilterSocketKind::Tcp6,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Unsupported socket_filter socket kind: {socket_kind}. Expected udp4, udp6, tcp4, or tcp6"
                )));
            }
        };

        let bind_ip = match socket_kind {
            SocketFilterSocketKind::Udp4 | SocketFilterSocketKind::Tcp4 => {
                bind_ip.parse::<Ipv4Addr>().map_err(|e| {
                    ProgramSpecParseError::new(format!(
                        "Invalid socket_filter IPv4 bind address '{bind_ip}': {e}"
                    ))
                })?;
                bind_ip.to_string()
            }
            SocketFilterSocketKind::Udp6 | SocketFilterSocketKind::Tcp6 => {
                let inner = bind_ip
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .ok_or_else(|| {
                        ProgramSpecParseError::new(format!(
                            "Invalid socket_filter IPv6 bind address '{bind_ip}': expected brackets like [::1]"
                        ))
                    })?;
                inner.parse::<Ipv6Addr>().map_err(|e| {
                    ProgramSpecParseError::new(format!(
                        "Invalid socket_filter IPv6 bind address '{inner}': {e}"
                    ))
                })?;
                inner.to_string()
            }
        };

        let bind_port = bind_port.parse::<u16>().map_err(|e| {
            ProgramSpecParseError::new(format!("Invalid socket_filter port '{bind_port}': {e}"))
        })?;
        if bind_port == 0 {
            return Err(ProgramSpecParseError::new(
                "socket_filter port must be non-zero",
            ));
        }

        Ok(Self {
            socket_kind,
            bind_ip,
            bind_port,
        })
    }

    pub fn target_string(&self) -> String {
        let bind_ip = match self.socket_kind {
            SocketFilterSocketKind::Udp4 | SocketFilterSocketKind::Tcp4 => self.bind_ip.clone(),
            SocketFilterSocketKind::Udp6 | SocketFilterSocketKind::Tcp6 => {
                format!("[{}]", self.bind_ip)
            }
        };
        format!("{}:{}:{}", self.socket_kind.name(), bind_ip, self.bind_port)
    }
}

/// Parsed cgroup_sock_addr target information.
#[derive(Debug, Clone)]
pub struct CgroupSockAddrTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
    /// Attach kind.
    pub attach_type: CgroupSockAddrAttachType,
}

impl CgroupSockAddrTarget {
    /// Parse a cgroup_sock_addr target string of the form `/sys/fs/cgroup:connect4`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (cgroup_path, attach_kind) = target.rsplit_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid cgroup_sock_addr target: {target}. Expected format: /path/to/cgroup:attach_kind"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(ProgramSpecParseError::new(
                "cgroup_sock_addr cgroup path cannot be empty",
            ));
        }

        let attach_type = match attach_kind {
            "bind4" => CgroupSockAddrAttachType::Bind4,
            "bind6" => CgroupSockAddrAttachType::Bind6,
            "connect4" => CgroupSockAddrAttachType::Connect4,
            "connect6" => CgroupSockAddrAttachType::Connect6,
            "getpeername4" => CgroupSockAddrAttachType::GetPeerName4,
            "getpeername6" => CgroupSockAddrAttachType::GetPeerName6,
            "getsockname4" => CgroupSockAddrAttachType::GetSockName4,
            "getsockname6" => CgroupSockAddrAttachType::GetSockName6,
            "sendmsg4" => CgroupSockAddrAttachType::UDPSendMsg4,
            "sendmsg6" => CgroupSockAddrAttachType::UDPSendMsg6,
            "recvmsg4" => CgroupSockAddrAttachType::UDPRecvMsg4,
            "recvmsg6" => CgroupSockAddrAttachType::UDPRecvMsg6,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid cgroup_sock_addr attach kind: {attach_kind}. Expected one of bind4, bind6, connect4, connect6, getpeername4, getpeername6, getsockname4, getsockname6, sendmsg4, sendmsg6, recvmsg4, recvmsg6"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }

    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSockAddrAttachType::Bind4 => "bind4",
            CgroupSockAddrAttachType::Bind6 => "bind6",
            CgroupSockAddrAttachType::Connect4 => "connect4",
            CgroupSockAddrAttachType::Connect6 => "connect6",
            CgroupSockAddrAttachType::GetPeerName4 => "getpeername4",
            CgroupSockAddrAttachType::GetPeerName6 => "getpeername6",
            CgroupSockAddrAttachType::GetSockName4 => "getsockname4",
            CgroupSockAddrAttachType::GetSockName6 => "getsockname6",
            CgroupSockAddrAttachType::UDPSendMsg4 => "sendmsg4",
            CgroupSockAddrAttachType::UDPSendMsg6 => "sendmsg6",
            CgroupSockAddrAttachType::UDPRecvMsg4 => "recvmsg4",
            CgroupSockAddrAttachType::UDPRecvMsg6 => "recvmsg6",
        }
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }

    pub fn section_name(&self) -> String {
        format!("cgroup/{}", self.attach_type_name())
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(
            self.attach_type,
            CgroupSockAddrAttachType::Bind4
                | CgroupSockAddrAttachType::Connect4
                | CgroupSockAddrAttachType::GetPeerName4
                | CgroupSockAddrAttachType::GetSockName4
                | CgroupSockAddrAttachType::UDPSendMsg4
                | CgroupSockAddrAttachType::UDPRecvMsg4
        )
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(
            self.attach_type,
            CgroupSockAddrAttachType::Bind6
                | CgroupSockAddrAttachType::Connect6
                | CgroupSockAddrAttachType::GetPeerName6
                | CgroupSockAddrAttachType::GetSockName6
                | CgroupSockAddrAttachType::UDPSendMsg6
                | CgroupSockAddrAttachType::UDPRecvMsg6
        )
    }

    pub fn has_msg_source(&self) -> bool {
        matches!(
            self.attach_type,
            CgroupSockAddrAttachType::UDPSendMsg4
                | CgroupSockAddrAttachType::UDPSendMsg6
                | CgroupSockAddrAttachType::UDPRecvMsg4
                | CgroupSockAddrAttachType::UDPRecvMsg6
        )
    }

    pub fn is_connect(&self) -> bool {
        matches!(
            self.attach_type,
            CgroupSockAddrAttachType::Connect4 | CgroupSockAddrAttachType::Connect6
        )
    }
}

impl PartialEq for CgroupSockAddrTarget {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_path == other.cgroup_path && self.attach_type_name() == other.attach_type_name()
    }
}

impl Eq for CgroupSockAddrTarget {}

/// Parsed cgroup_sockopt target information.
#[derive(Debug, Clone)]
pub struct CgroupSockoptTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
    /// Attach kind.
    pub attach_type: CgroupSockoptAttachType,
}

impl CgroupSockoptTarget {
    /// Parse a cgroup_sockopt target string of the form `/sys/fs/cgroup:get`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (cgroup_path, attach_kind) = target.rsplit_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid cgroup_sockopt target: {target}. Expected format: /path/to/cgroup:get or /path/to/cgroup:set"
            ))
        })?;

        if cgroup_path.is_empty() {
            return Err(ProgramSpecParseError::new(
                "cgroup_sockopt cgroup path cannot be empty",
            ));
        }

        let attach_type = match attach_kind {
            "get" => CgroupSockoptAttachType::Get,
            "set" => CgroupSockoptAttachType::Set,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid cgroup_sockopt attach kind: {attach_kind}. Expected get or set"
                )));
            }
        };

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }

    pub fn attach_type_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSockoptAttachType::Get => "get",
            CgroupSockoptAttachType::Set => "set",
        }
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }

    pub fn section_name(&self) -> &'static str {
        match self.attach_type {
            CgroupSockoptAttachType::Get => "cgroup/getsockopt",
            CgroupSockoptAttachType::Set => "cgroup/setsockopt",
        }
    }

    pub fn is_get(&self) -> bool {
        matches!(self.attach_type, CgroupSockoptAttachType::Get)
    }
}

impl PartialEq for CgroupSockoptTarget {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_path == other.cgroup_path && self.attach_type_name() == other.attach_type_name()
    }
}

impl Eq for CgroupSockoptTarget {}

/// Parsed sk_lookup target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkLookupTarget {
    /// Filesystem path to the network namespace file.
    pub netns_path: String,
}

impl SkLookupTarget {
    /// Parse an sk_lookup target string of the form `/proc/self/ns/net`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "sk_lookup network namespace path cannot be empty",
            ));
        }

        Ok(Self {
            netns_path: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.netns_path.clone()
    }
}

/// Parsed lirc_mode2 target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LircMode2Target {
    /// Filesystem path to the lirc device.
    pub device_path: String,
}

impl LircMode2Target {
    /// Parse a lirc_mode2 target string of the form `/dev/lirc0`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "lirc_mode2 device path cannot be empty",
            ));
        }

        Ok(Self {
            device_path: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.device_path.clone()
    }
}

pub const DEFAULT_PERF_EVENT_PERIOD: u64 = 1_000_000;

/// Supported software perf events for the initial perf_event program surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventSoftwareEvent {
    CpuClock,
    TaskClock,
    ContextSwitches,
    CpuMigrations,
    PageFaults,
    MinorFaults,
    MajorFaults,
}

impl PerfEventSoftwareEvent {
    pub fn name(&self) -> &'static str {
        match self {
            PerfEventSoftwareEvent::CpuClock => "cpu-clock",
            PerfEventSoftwareEvent::TaskClock => "task-clock",
            PerfEventSoftwareEvent::ContextSwitches => "context-switches",
            PerfEventSoftwareEvent::CpuMigrations => "cpu-migrations",
            PerfEventSoftwareEvent::PageFaults => "page-faults",
            PerfEventSoftwareEvent::MinorFaults => "minor-faults",
            PerfEventSoftwareEvent::MajorFaults => "major-faults",
        }
    }
}

/// Supported hardware perf events for the initial perf_event hardware surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventHardwareEvent {
    CpuCycles,
    Instructions,
    CacheReferences,
    CacheMisses,
    BranchInstructions,
    BranchMisses,
    BusCycles,
    StalledCyclesFrontend,
    StalledCyclesBackend,
    RefCpuCycles,
}

impl PerfEventHardwareEvent {
    pub fn name(&self) -> &'static str {
        match self {
            PerfEventHardwareEvent::CpuCycles => "cpu-cycles",
            PerfEventHardwareEvent::Instructions => "instructions",
            PerfEventHardwareEvent::CacheReferences => "cache-references",
            PerfEventHardwareEvent::CacheMisses => "cache-misses",
            PerfEventHardwareEvent::BranchInstructions => "branch-instructions",
            PerfEventHardwareEvent::BranchMisses => "branch-misses",
            PerfEventHardwareEvent::BusCycles => "bus-cycles",
            PerfEventHardwareEvent::StalledCyclesFrontend => "stalled-cycles-frontend",
            PerfEventHardwareEvent::StalledCyclesBackend => "stalled-cycles-backend",
            PerfEventHardwareEvent::RefCpuCycles => "ref-cpu-cycles",
        }
    }
}

/// Supported perf_event sources and their event selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventEvent {
    Software(PerfEventSoftwareEvent),
    Hardware(PerfEventHardwareEvent),
}

impl PerfEventEvent {
    pub fn source_name(&self) -> &'static str {
        match self {
            PerfEventEvent::Software(_) => "software",
            PerfEventEvent::Hardware(_) => "hardware",
        }
    }

    pub fn event_name(&self) -> &'static str {
        match self {
            PerfEventEvent::Software(event) => event.name(),
            PerfEventEvent::Hardware(event) => event.name(),
        }
    }
}

/// Sample policy for perf_event programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventSamplePolicy {
    Period(u64),
    Frequency(u64),
}

impl PerfEventSamplePolicy {
    pub fn is_default(&self) -> bool {
        matches!(
            self,
            PerfEventSamplePolicy::Period(DEFAULT_PERF_EVENT_PERIOD)
        )
    }
}

/// Parsed perf_event target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfEventTarget {
    /// Perf event source and selector.
    pub event: PerfEventEvent,
    /// Optional CPU selector. `None` means attach on all online CPUs.
    pub cpu: Option<u32>,
    /// Optional PID selector. `None` means attach across processes.
    pub pid: Option<u32>,
    /// Perf sampling policy.
    pub sample_policy: PerfEventSamplePolicy,
}

impl PerfEventTarget {
    /// Parse a perf_event target string of the form
    /// `software:cpu-clock[:cpu=0][:pid=1234][:period=1000000]` or
    /// `hardware:cpu-cycles[:cpu=0][:pid=1234][:period=1000000]`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let mut parts = target.split(':');
        let source = parts.next().ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid perf_event target: {target}. Expected format: software:cpu-clock[:cpu=N][:pid=N][:period=N|freq=N] or hardware:cpu-cycles[:cpu=N][:pid=N][:period=N|freq=N]"
            ))
        })?;
        let event_name = parts.next().ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid perf_event target: {target}. Expected format: software:cpu-clock[:cpu=N][:pid=N][:period=N|freq=N] or hardware:cpu-cycles[:cpu=N][:pid=N][:period=N|freq=N]"
            ))
        })?;

        let event = match source {
            "software" => match event_name {
                "cpu-clock" => PerfEventEvent::Software(PerfEventSoftwareEvent::CpuClock),
                "task-clock" => PerfEventEvent::Software(PerfEventSoftwareEvent::TaskClock),
                "context-switches" => {
                    PerfEventEvent::Software(PerfEventSoftwareEvent::ContextSwitches)
                }
                "cpu-migrations" => PerfEventEvent::Software(PerfEventSoftwareEvent::CpuMigrations),
                "page-faults" => PerfEventEvent::Software(PerfEventSoftwareEvent::PageFaults),
                "minor-faults" => PerfEventEvent::Software(PerfEventSoftwareEvent::MinorFaults),
                "major-faults" => PerfEventEvent::Software(PerfEventSoftwareEvent::MajorFaults),
                _ => {
                    return Err(ProgramSpecParseError::new(format!(
                        "Unsupported perf_event software event: {event_name}. Expected one of cpu-clock, task-clock, context-switches, cpu-migrations, page-faults, minor-faults, major-faults"
                    )));
                }
            },
            "hardware" => match event_name {
                "cpu-cycles" => PerfEventEvent::Hardware(PerfEventHardwareEvent::CpuCycles),
                "instructions" => PerfEventEvent::Hardware(PerfEventHardwareEvent::Instructions),
                "cache-references" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::CacheReferences)
                }
                "cache-misses" => PerfEventEvent::Hardware(PerfEventHardwareEvent::CacheMisses),
                "branch-instructions" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::BranchInstructions)
                }
                "branch-misses" => PerfEventEvent::Hardware(PerfEventHardwareEvent::BranchMisses),
                "bus-cycles" => PerfEventEvent::Hardware(PerfEventHardwareEvent::BusCycles),
                "stalled-cycles-frontend" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::StalledCyclesFrontend)
                }
                "stalled-cycles-backend" => {
                    PerfEventEvent::Hardware(PerfEventHardwareEvent::StalledCyclesBackend)
                }
                "ref-cpu-cycles" => PerfEventEvent::Hardware(PerfEventHardwareEvent::RefCpuCycles),
                _ => {
                    return Err(ProgramSpecParseError::new(format!(
                        "Unsupported perf_event hardware event: {event_name}. Expected one of cpu-cycles, instructions, cache-references, cache-misses, branch-instructions, branch-misses, bus-cycles, stalled-cycles-frontend, stalled-cycles-backend, ref-cpu-cycles"
                    )));
                }
            },
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Unsupported perf_event source: {source}. Expected software or hardware"
                )));
            }
        };

        let mut cpu = None;
        let mut pid = None;
        let mut sample_policy = PerfEventSamplePolicy::Period(DEFAULT_PERF_EVENT_PERIOD);

        for option in parts {
            if let Some(raw_cpu) = option.strip_prefix("cpu=") {
                if cpu.is_some() {
                    return Err(ProgramSpecParseError::new(
                        "perf_event target cannot specify cpu more than once",
                    ));
                }
                cpu = Some(raw_cpu.parse::<u32>().map_err(|_| {
                    ProgramSpecParseError::new(format!(
                        "Invalid perf_event cpu selector: {raw_cpu}"
                    ))
                })?);
                continue;
            }

            if let Some(raw_pid) = option.strip_prefix("pid=") {
                if pid.is_some() {
                    return Err(ProgramSpecParseError::new(
                        "perf_event target cannot specify pid more than once",
                    ));
                }
                let parsed_pid = raw_pid.parse::<u32>().map_err(|_| {
                    ProgramSpecParseError::new(format!(
                        "Invalid perf_event pid selector: {raw_pid}"
                    ))
                })?;
                if parsed_pid == 0 {
                    return Err(ProgramSpecParseError::new(
                        "perf_event pid selector must be greater than zero",
                    ));
                }
                pid = Some(parsed_pid);
                continue;
            }

            if let Some(raw_period) = option.strip_prefix("period=") {
                let period = raw_period.parse::<u64>().map_err(|_| {
                    ProgramSpecParseError::new(format!("Invalid perf_event period: {raw_period}"))
                })?;
                if period == 0 {
                    return Err(ProgramSpecParseError::new(
                        "perf_event period must be greater than zero",
                    ));
                }
                match sample_policy {
                    PerfEventSamplePolicy::Period(v) if v == DEFAULT_PERF_EVENT_PERIOD => {
                        sample_policy = PerfEventSamplePolicy::Period(period);
                    }
                    _ => {
                        return Err(ProgramSpecParseError::new(
                            "perf_event target cannot specify both period and freq",
                        ));
                    }
                }
                continue;
            }

            if let Some(raw_freq) = option.strip_prefix("freq=") {
                let freq = raw_freq.parse::<u64>().map_err(|_| {
                    ProgramSpecParseError::new(format!("Invalid perf_event frequency: {raw_freq}"))
                })?;
                if freq == 0 {
                    return Err(ProgramSpecParseError::new(
                        "perf_event frequency must be greater than zero",
                    ));
                }
                if !matches!(
                    sample_policy,
                    PerfEventSamplePolicy::Period(v) if v == DEFAULT_PERF_EVENT_PERIOD
                ) {
                    return Err(ProgramSpecParseError::new(
                        "perf_event target cannot specify both period and freq",
                    ));
                }
                sample_policy = PerfEventSamplePolicy::Frequency(freq);
                continue;
            }

            return Err(ProgramSpecParseError::new(format!(
                "Unrecognized perf_event selector: {option}. Expected cpu=N, pid=N, period=N, or freq=N"
            )));
        }

        Ok(Self {
            event,
            cpu,
            pid,
            sample_policy,
        })
    }

    pub fn target_string(&self) -> String {
        let mut target = format!("{}:{}", self.event.source_name(), self.event.event_name());
        if let Some(cpu) = self.cpu {
            target.push_str(&format!(":cpu={cpu}"));
        }
        if let Some(pid) = self.pid {
            target.push_str(&format!(":pid={pid}"));
        }
        match self.sample_policy {
            PerfEventSamplePolicy::Period(period) if period != DEFAULT_PERF_EVENT_PERIOD => {
                target.push_str(&format!(":period={period}"));
            }
            PerfEventSamplePolicy::Frequency(freq) => {
                target.push_str(&format!(":freq={freq}"));
            }
            _ => {}
        }
        target
    }
}

/// Parsed program specification with structured target metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramSpec {
    Kprobe { function: String },
    Kretprobe { function: String },
    Fentry { function: String },
    Fexit { function: String },
    TpBtf { name: String },
    Lsm { hook: String },
    Tracepoint { category: String, name: String },
    RawTracepoint { name: String },
    Uprobe { target: UprobeTarget },
    Uretprobe { target: UprobeTarget },
    Xdp { interface: String },
    PerfEvent { target: PerfEventTarget },
    SocketFilter { target: SocketFilterTarget },
    SkLookup { target: SkLookupTarget },
    SkMsg { target: SkMsgTarget },
    SkSkb { target: SkSkbTarget },
    SkSkbParser { target: SkSkbTarget },
    CgroupDevice { target: CgroupDeviceTarget },
    SockOps { target: SockOpsTarget },
    Tc { target: TcTarget },
    CgroupSkb { target: CgroupSkbTarget },
    CgroupSock { target: CgroupSockTarget },
    CgroupSysctl { cgroup_path: String },
    CgroupSockopt { target: CgroupSockoptTarget },
    CgroupSockAddr { target: CgroupSockAddrTarget },
    LircMode2 { target: LircMode2Target },
    StructOps { value_type_name: String },
}

impl ProgramSpec {
    pub fn parse(spec: &str) -> Result<Self, ProgramSpecParseError> {
        let Some((prefix, target)) = spec.split_once(':') else {
            return Err(ProgramSpecParseError::new(format!(
                "Invalid probe spec: {spec}. Expected format: type:target (e.g., kprobe:sys_clone)"
            )));
        };

        let Some(prog_type) = EbpfProgramType::from_spec_prefix(prefix) else {
            return Err(ProgramSpecParseError::new(format!(
                "Unknown probe type: {prefix}. Supported: {}",
                EbpfProgramType::supported_spec_prefixes().join(", ")
            )));
        };

        Self::from_program_type_target(prog_type, target)
    }

    pub fn from_program_type_target(
        prog_type: EbpfProgramType,
        target: &str,
    ) -> Result<Self, ProgramSpecParseError> {
        match prog_type {
            EbpfProgramType::Kprobe => Ok(ProgramSpec::Kprobe {
                function: target.to_string(),
            }),
            EbpfProgramType::Kretprobe => Ok(ProgramSpec::Kretprobe {
                function: target.to_string(),
            }),
            EbpfProgramType::Fentry => Ok(ProgramSpec::Fentry {
                function: target.to_string(),
            }),
            EbpfProgramType::Fexit => Ok(ProgramSpec::Fexit {
                function: target.to_string(),
            }),
            EbpfProgramType::TpBtf => Ok(ProgramSpec::TpBtf {
                name: target.to_string(),
            }),
            EbpfProgramType::Lsm => Ok(ProgramSpec::Lsm {
                hook: target.to_string(),
            }),
            EbpfProgramType::Tracepoint => {
                let (category, name) = target.split_once('/').ok_or_else(|| {
                    ProgramSpecParseError::new(format!(
                        "Invalid tracepoint target: {target}. Expected format: category/name"
                    ))
                })?;
                Ok(ProgramSpec::Tracepoint {
                    category: category.to_string(),
                    name: name.to_string(),
                })
            }
            EbpfProgramType::RawTracepoint => Ok(ProgramSpec::RawTracepoint {
                name: target.to_string(),
            }),
            EbpfProgramType::Uprobe => Ok(ProgramSpec::Uprobe {
                target: UprobeTarget::parse(target)?,
            }),
            EbpfProgramType::Uretprobe => Ok(ProgramSpec::Uretprobe {
                target: UprobeTarget::parse(target)?,
            }),
            EbpfProgramType::Xdp => Ok(ProgramSpec::Xdp {
                interface: target.to_string(),
            }),
            EbpfProgramType::PerfEvent => Ok(ProgramSpec::PerfEvent {
                target: PerfEventTarget::parse(target)?,
            }),
            EbpfProgramType::SocketFilter => Ok(ProgramSpec::SocketFilter {
                target: SocketFilterTarget::parse(target)?,
            }),
            EbpfProgramType::SkLookup => Ok(ProgramSpec::SkLookup {
                target: SkLookupTarget::parse(target)?,
            }),
            EbpfProgramType::SkMsg => Ok(ProgramSpec::SkMsg {
                target: SkMsgTarget::parse(target)?,
            }),
            EbpfProgramType::SkSkb => Ok(ProgramSpec::SkSkb {
                target: SkSkbTarget::parse(target)?,
            }),
            EbpfProgramType::SkSkbParser => Ok(ProgramSpec::SkSkbParser {
                target: SkSkbTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupDevice => Ok(ProgramSpec::CgroupDevice {
                target: CgroupDeviceTarget::parse(target)?,
            }),
            EbpfProgramType::SockOps => Ok(ProgramSpec::SockOps {
                target: SockOpsTarget::parse(target)?,
            }),
            EbpfProgramType::Tc => Ok(ProgramSpec::Tc {
                target: TcTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSkb => Ok(ProgramSpec::CgroupSkb {
                target: CgroupSkbTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSock => Ok(ProgramSpec::CgroupSock {
                target: CgroupSockTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSysctl => Ok(ProgramSpec::CgroupSysctl {
                cgroup_path: target.to_string(),
            }),
            EbpfProgramType::CgroupSockopt => Ok(ProgramSpec::CgroupSockopt {
                target: CgroupSockoptTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSockAddr => Ok(ProgramSpec::CgroupSockAddr {
                target: CgroupSockAddrTarget::parse(target)?,
            }),
            EbpfProgramType::LircMode2 => Ok(ProgramSpec::LircMode2 {
                target: LircMode2Target::parse(target)?,
            }),
            EbpfProgramType::StructOps => Ok(ProgramSpec::StructOps {
                value_type_name: target.to_string(),
            }),
        }
    }

    pub fn program_type(&self) -> EbpfProgramType {
        match self {
            ProgramSpec::Kprobe { .. } => EbpfProgramType::Kprobe,
            ProgramSpec::Kretprobe { .. } => EbpfProgramType::Kretprobe,
            ProgramSpec::Fentry { .. } => EbpfProgramType::Fentry,
            ProgramSpec::Fexit { .. } => EbpfProgramType::Fexit,
            ProgramSpec::TpBtf { .. } => EbpfProgramType::TpBtf,
            ProgramSpec::Lsm { .. } => EbpfProgramType::Lsm,
            ProgramSpec::Tracepoint { .. } => EbpfProgramType::Tracepoint,
            ProgramSpec::RawTracepoint { .. } => EbpfProgramType::RawTracepoint,
            ProgramSpec::Uprobe { .. } => EbpfProgramType::Uprobe,
            ProgramSpec::Uretprobe { .. } => EbpfProgramType::Uretprobe,
            ProgramSpec::Xdp { .. } => EbpfProgramType::Xdp,
            ProgramSpec::PerfEvent { .. } => EbpfProgramType::PerfEvent,
            ProgramSpec::SocketFilter { .. } => EbpfProgramType::SocketFilter,
            ProgramSpec::SkLookup { .. } => EbpfProgramType::SkLookup,
            ProgramSpec::SkMsg { .. } => EbpfProgramType::SkMsg,
            ProgramSpec::SkSkb { .. } => EbpfProgramType::SkSkb,
            ProgramSpec::SkSkbParser { .. } => EbpfProgramType::SkSkbParser,
            ProgramSpec::CgroupDevice { .. } => EbpfProgramType::CgroupDevice,
            ProgramSpec::SockOps { .. } => EbpfProgramType::SockOps,
            ProgramSpec::Tc { .. } => EbpfProgramType::Tc,
            ProgramSpec::CgroupSkb { .. } => EbpfProgramType::CgroupSkb,
            ProgramSpec::CgroupSock { .. } => EbpfProgramType::CgroupSock,
            ProgramSpec::CgroupSysctl { .. } => EbpfProgramType::CgroupSysctl,
            ProgramSpec::CgroupSockopt { .. } => EbpfProgramType::CgroupSockopt,
            ProgramSpec::CgroupSockAddr { .. } => EbpfProgramType::CgroupSockAddr,
            ProgramSpec::LircMode2 { .. } => EbpfProgramType::LircMode2,
            ProgramSpec::StructOps { .. } => EbpfProgramType::StructOps,
        }
    }

    pub fn target_string(&self) -> String {
        match self {
            ProgramSpec::Kprobe { function }
            | ProgramSpec::Kretprobe { function }
            | ProgramSpec::Fentry { function }
            | ProgramSpec::Fexit { function } => function.clone(),
            ProgramSpec::TpBtf { name } => name.clone(),
            ProgramSpec::Lsm { hook } => hook.clone(),
            ProgramSpec::Tracepoint { category, name } => format!("{category}/{name}"),
            ProgramSpec::RawTracepoint { name } => name.clone(),
            ProgramSpec::Uprobe { target } | ProgramSpec::Uretprobe { target } => {
                target.target_string()
            }
            ProgramSpec::Xdp { interface } => interface.clone(),
            ProgramSpec::PerfEvent { target } => target.target_string(),
            ProgramSpec::SocketFilter { target } => target.target_string(),
            ProgramSpec::SkLookup { target } => target.target_string(),
            ProgramSpec::SkMsg { target } => target.target_string(),
            ProgramSpec::SkSkb { target } => target.target_string(),
            ProgramSpec::SkSkbParser { target } => target.target_string(),
            ProgramSpec::CgroupDevice { target } => target.target_string(),
            ProgramSpec::SockOps { target } => target.target_string(),
            ProgramSpec::Tc { target } => target.target_string(),
            ProgramSpec::CgroupSkb { target } => target.target_string(),
            ProgramSpec::CgroupSock { target } => target.target_string(),
            ProgramSpec::CgroupSysctl { cgroup_path } => cgroup_path.clone(),
            ProgramSpec::CgroupSockopt { target } => target.target_string(),
            ProgramSpec::CgroupSockAddr { target } => target.target_string(),
            ProgramSpec::LircMode2 { target } => target.target_string(),
            ProgramSpec::StructOps { value_type_name } => value_type_name.clone(),
        }
    }

    pub fn section_name(&self) -> String {
        match self {
            ProgramSpec::CgroupSkb { target } => target.section_name(),
            ProgramSpec::CgroupSock { target } => target.section_name(),
            ProgramSpec::CgroupSysctl { .. } => "cgroup/sysctl".to_string(),
            ProgramSpec::CgroupSockopt { target } => target.section_name().to_string(),
            ProgramSpec::CgroupSockAddr { target } => target.section_name(),
            ProgramSpec::CgroupDevice { target } => target.section_name().to_string(),
            _ => {
                let prog_type = self.program_type();
                if prog_type.info().section_uses_target {
                    format!("{}/{}", prog_type.section_prefix(), self.target_string())
                } else {
                    prog_type.section_prefix().to_string()
                }
            }
        }
    }
}

impl fmt::Display for ProgramSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.program_type().canonical_prefix(),
            self.target_string()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_sock_addr_target_attach_shape_helpers() {
        let connect4 = CgroupSockAddrTarget::parse("/sys/fs/cgroup:connect4")
            .expect("connect4 target should parse");
        assert!(connect4.is_ipv4());
        assert!(!connect4.is_ipv6());
        assert!(!connect4.has_msg_source());
        assert!(connect4.is_connect());

        let sendmsg6 = CgroupSockAddrTarget::parse("/sys/fs/cgroup:sendmsg6")
            .expect("sendmsg6 target should parse");
        assert!(!sendmsg6.is_ipv4());
        assert!(sendmsg6.is_ipv6());
        assert!(sendmsg6.has_msg_source());
        assert!(!sendmsg6.is_connect());
    }

    #[test]
    fn test_cgroup_sockopt_target_attach_shape_helpers() {
        let get =
            CgroupSockoptTarget::parse("/sys/fs/cgroup:get").expect("get target should parse");
        let set =
            CgroupSockoptTarget::parse("/sys/fs/cgroup:set").expect("set target should parse");

        assert!(get.is_get());
        assert!(!set.is_get());
    }
}
