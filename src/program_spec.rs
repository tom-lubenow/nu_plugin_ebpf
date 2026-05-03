use crate::compiler::{
    EbpfProgramType, ProgramAttachKind, ProgramBtfCallableSurface, ProgramCompatibilityRequirement,
    ProgramTargetKind, ProgramValueAccess,
};
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

/// Parsed uprobe.multi/uretprobe.multi target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UprobeMultiTarget {
    /// Path to the binary or library.
    pub binary_path: String,
    /// Function name or wildcard pattern matched by the loader.
    pub function_pattern: String,
}

impl UprobeMultiTarget {
    /// Parse a uprobe.multi target string.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (binary_path, function_pattern) = target.split_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid uprobe.multi target: {target}. Expected format: /path/to/binary:function_pattern"
            ))
        })?;

        if binary_path.is_empty() {
            return Err(ProgramSpecParseError::new(
                "uprobe.multi binary path cannot be empty",
            ));
        }
        if function_pattern.is_empty() {
            return Err(ProgramSpecParseError::new(
                "uprobe.multi function pattern cannot be empty",
            ));
        }

        Ok(Self {
            binary_path: binary_path.to_string(),
            function_pattern: function_pattern.to_string(),
        })
    }

    /// Render this parsed target back into canonical target syntax.
    pub fn target_string(&self) -> String {
        format!("{}:{}", self.binary_path, self.function_pattern)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructOpsFamily {
    Generic,
    TcpCongestion,
    HidBpf,
    SchedExt,
    Qdisc,
}

impl StructOpsFamily {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::TcpCongestion => "tcp-congestion",
            Self::HidBpf => "hid-bpf",
            Self::SchedExt => "sched-ext",
            Self::Qdisc => "qdisc",
        }
    }

    pub(crate) fn from_value_type_name(value_type_name: &str) -> Self {
        match value_type_name {
            "tcp_congestion_ops" => Self::TcpCongestion,
            "hid_bpf_ops" => Self::HidBpf,
            "sched_ext_ops" => Self::SchedExt,
            "Qdisc_ops" => Self::Qdisc,
            _ => Self::Generic,
        }
    }

    pub(crate) fn live_attach_risk(self) -> Option<&'static str> {
        match self {
            Self::SchedExt => Some(
                "live sched_ext registration can disrupt host scheduling; prefer --dry-run on the host and use a VM or disposable environment for real loads",
            ),
            Self::HidBpf => Some(
                "live hid_bpf_ops registration can alter HID input and report handling; prefer --dry-run on the host and use an isolated device or disposable environment for real loads",
            ),
            Self::Qdisc => Some(
                "live Qdisc_ops registration can affect packet scheduling; prefer --dry-run on the host and use an isolated network namespace or VM for real loads",
            ),
            Self::Generic | Self::TcpCongestion => None,
        }
    }

    pub(crate) fn callback_is_sleepable(self, callback_name: &str) -> bool {
        match self {
            // sched_ext documents these callbacks as sleepable and they must be
            // emitted under `struct_ops.s/...` rather than plain `struct_ops/...`.
            Self::SchedExt => matches!(
                callback_name,
                "init_task"
                    | "cgroup_init"
                    | "cgroup_exit"
                    | "cgroup_prep_move"
                    | "cpu_online"
                    | "cpu_offline"
                    | "init"
                    | "exit"
            ),
            Self::Generic | Self::TcpCongestion | Self::HidBpf | Self::Qdisc => false,
        }
    }
}

pub(crate) fn struct_ops_callback_is_sleepable(value_type_name: &str, callback_name: &str) -> bool {
    StructOpsFamily::from_value_type_name(value_type_name).callback_is_sleepable(callback_name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramLiveAttachPolicy {
    pub loader_supported: bool,
    pub default_allowed: bool,
    pub requires_opt_in: bool,
    pub note: Option<&'static str>,
}

pub(crate) const CGROUP_SOCK_ADDR_UNIX_LIVE_ATTACH_UNSUPPORTED: &str =
    "the current Aya cgroup_sock_addr attach surface does not expose BPF_CGROUP_UNIX_* hooks";

impl ProgramLiveAttachPolicy {
    fn unsupported(note: &'static str) -> Self {
        Self {
            loader_supported: false,
            default_allowed: false,
            requires_opt_in: false,
            note: Some(note),
        }
    }

    fn from_attach_kind_and_risk(
        attach_kind: ProgramAttachKind,
        risk: Option<&'static str>,
    ) -> Self {
        let unsupported = attach_kind.unsupported_live_attach_detail();
        let loader_supported = unsupported.is_none();
        let requires_opt_in = loader_supported && risk.is_some();
        Self {
            loader_supported,
            default_allowed: loader_supported && !requires_opt_in,
            requires_opt_in,
            note: unsupported.or(risk),
        }
    }
}

/// Parsed xdp target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpTarget {
    /// Network interface name.
    pub interface: String,
    /// XDP attach mode. Defaults to SKB/generic mode for safer development attaches.
    pub attach_mode: XdpAttachMode,
    /// Whether the program is multi-buffer capable (`xdp.frags` section).
    pub frags: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAttachMode {
    Skb,
    Driver,
    Hardware,
}

impl XdpAttachMode {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Skb => "skb",
            Self::Driver => "drv",
            Self::Hardware => "hw",
        }
    }
}

impl XdpTarget {
    /// Parse an xdp target string of the form `interface[:skb|drv|hw][:frags]`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let mut parts = target.split(':');
        let interface = parts.next().unwrap_or_default();
        if interface.is_empty() {
            return Err(ProgramSpecParseError::new(
                "xdp interface target cannot be empty",
            ));
        }

        let mut attach_mode = XdpAttachMode::Skb;
        let mut explicit_mode = false;
        let mut frags = false;

        for option in parts {
            match option {
                "frags" if !frags => frags = true,
                "frags" => {
                    return Err(ProgramSpecParseError::new(
                        "xdp target contains duplicate frags option",
                    ));
                }
                "skb" | "generic" if !explicit_mode => {
                    attach_mode = XdpAttachMode::Skb;
                    explicit_mode = true;
                }
                "drv" | "driver" | "native" if !explicit_mode => {
                    attach_mode = XdpAttachMode::Driver;
                    explicit_mode = true;
                }
                "hw" | "hardware" | "offload" if !explicit_mode => {
                    attach_mode = XdpAttachMode::Hardware;
                    explicit_mode = true;
                }
                "skb" | "generic" | "drv" | "driver" | "native" | "hw" | "hardware" | "offload" => {
                    return Err(ProgramSpecParseError::new(
                        "xdp target accepts at most one attach mode",
                    ));
                }
                "" => {
                    return Err(ProgramSpecParseError::new(
                        "xdp target option cannot be empty",
                    ));
                }
                option => {
                    return Err(ProgramSpecParseError::new(format!(
                        "Invalid xdp target option: {option}. Expected format: interface[:skb|drv|hw][:frags]"
                    )));
                }
            }
        }

        Ok(Self {
            interface: interface.to_string(),
            attach_mode,
            frags,
        })
    }

    pub fn target_string(&self) -> String {
        let mut target = self.interface.clone();
        if self.attach_mode != XdpAttachMode::Skb {
            target.push(':');
            target.push_str(self.attach_mode.key());
        }
        if self.frags {
            target.push_str(":frags");
        }
        target
    }

    pub fn section_name(&self) -> &'static str {
        if self.frags { "xdp.frags" } else { "xdp" }
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

/// Netkit device hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetkitAttachType {
    Primary,
    Peer,
}

impl NetkitAttachType {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Peer => "peer",
        }
    }
}

/// Parsed netkit target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetkitTarget {
    /// Netkit network interface name.
    pub interface: String,
    /// Netkit primary or peer hook.
    pub attach_type: NetkitAttachType,
}

impl NetkitTarget {
    /// Parse a netkit target string of the form `iface:primary` or `iface:peer`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let (interface, endpoint) = target.split_once(':').ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid netkit target: {target}. Expected format: interface:primary or interface:peer"
            ))
        })?;

        if interface.is_empty() {
            return Err(ProgramSpecParseError::new(
                "netkit interface target cannot be empty",
            ));
        }

        let attach_type = match endpoint {
            "primary" => NetkitAttachType::Primary,
            "peer" => NetkitAttachType::Peer,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid netkit endpoint: {endpoint}. Expected primary or peer"
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
            NetkitAttachType::Primary => "primary",
            NetkitAttachType::Peer => "peer",
        }
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.interface, self.attach_type_name())
    }

    pub fn section_name(&self) -> String {
        format!("netkit/{}", self.attach_type_name())
    }
}

/// Parsed traffic-control action target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcActionTarget {
    /// Descriptive action label. Live tc-action attach is not implemented yet.
    pub label: String,
}

impl TcActionTarget {
    /// Parse a tc_action target label. The compiler uses it for metadata only.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "tc_action target label cannot be empty",
            ));
        }

        Ok(Self {
            label: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.label.clone()
    }
}

/// Parsed freplace/extension target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionTarget {
    /// Global function name in the target BPF program to replace.
    pub function: String,
}

impl ExtensionTarget {
    /// Parse an extension target function name.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "freplace target function cannot be empty",
            ));
        }

        Ok(Self {
            function: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.function.clone()
    }
}

/// Parsed syscall program target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallTarget {
    /// Descriptive label. The emitted ELF section is always `syscall`.
    pub label: String,
}

impl SyscallTarget {
    /// Parse a syscall program metadata label.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "syscall target label cannot be empty",
            ));
        }

        Ok(Self {
            label: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.label.clone()
    }
}

/// Parsed BPF iterator target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IterTarget {
    /// Kernel iterator target, for example `task`.
    pub name: String,
}

impl IterTarget {
    /// Parse a BPF iterator target name.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "BPF iterator target cannot be empty",
            ));
        }

        Ok(Self {
            name: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.name.clone()
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

    pub fn is_ingress(&self) -> bool {
        matches!(self.attach_type, CgroupSkbAttachType::Ingress)
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

/// Parsed cgroup_sysctl target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupSysctlTarget {
    /// Filesystem path to the cgroup directory.
    pub cgroup_path: String,
}

impl CgroupSysctlTarget {
    /// Parse a cgroup_sysctl target string of the form `/sys/fs/cgroup`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "cgroup_sysctl cgroup path cannot be empty",
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
        "cgroup/sysctl"
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

    pub(crate) fn transport_key(self) -> &'static str {
        match self {
            Self::Udp4 | Self::Udp6 => "udp",
            Self::Tcp4 | Self::Tcp6 => "tcp",
        }
    }

    pub(crate) fn address_family(self) -> ProgramAttachAddressFamily {
        match self {
            Self::Udp4 | Self::Tcp4 => ProgramAttachAddressFamily::Ipv4,
            Self::Udp6 | Self::Tcp6 => ProgramAttachAddressFamily::Ipv6,
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
    pub attach_type: CgroupSockAddrAttachKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupSockAddrAttachKind {
    Bind4,
    Bind6,
    Connect4,
    Connect6,
    GetPeerName4,
    GetPeerName6,
    GetSockName4,
    GetSockName6,
    SendMsg4,
    SendMsg6,
    RecvMsg4,
    RecvMsg6,
    ConnectUnix,
    GetPeerNameUnix,
    GetSockNameUnix,
    SendMsgUnix,
    RecvMsgUnix,
}

impl CgroupSockAddrAttachKind {
    fn parse(attach_kind: &str) -> Option<Self> {
        Some(match attach_kind {
            "bind4" => Self::Bind4,
            "bind6" => Self::Bind6,
            "connect4" => Self::Connect4,
            "connect6" => Self::Connect6,
            "getpeername4" => Self::GetPeerName4,
            "getpeername6" => Self::GetPeerName6,
            "getsockname4" => Self::GetSockName4,
            "getsockname6" => Self::GetSockName6,
            "sendmsg4" => Self::SendMsg4,
            "sendmsg6" => Self::SendMsg6,
            "recvmsg4" => Self::RecvMsg4,
            "recvmsg6" => Self::RecvMsg6,
            "connect_unix" => Self::ConnectUnix,
            "getpeername_unix" => Self::GetPeerNameUnix,
            "getsockname_unix" => Self::GetSockNameUnix,
            "sendmsg_unix" => Self::SendMsgUnix,
            "recvmsg_unix" => Self::RecvMsgUnix,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Bind4 => "bind4",
            Self::Bind6 => "bind6",
            Self::Connect4 => "connect4",
            Self::Connect6 => "connect6",
            Self::GetPeerName4 => "getpeername4",
            Self::GetPeerName6 => "getpeername6",
            Self::GetSockName4 => "getsockname4",
            Self::GetSockName6 => "getsockname6",
            Self::SendMsg4 => "sendmsg4",
            Self::SendMsg6 => "sendmsg6",
            Self::RecvMsg4 => "recvmsg4",
            Self::RecvMsg6 => "recvmsg6",
            Self::ConnectUnix => "connect_unix",
            Self::GetPeerNameUnix => "getpeername_unix",
            Self::GetSockNameUnix => "getsockname_unix",
            Self::SendMsgUnix => "sendmsg_unix",
            Self::RecvMsgUnix => "recvmsg_unix",
        }
    }

    pub fn aya_attach_type(self) -> Option<CgroupSockAddrAttachType> {
        Some(match self {
            Self::Bind4 => CgroupSockAddrAttachType::Bind4,
            Self::Bind6 => CgroupSockAddrAttachType::Bind6,
            Self::Connect4 => CgroupSockAddrAttachType::Connect4,
            Self::Connect6 => CgroupSockAddrAttachType::Connect6,
            Self::GetPeerName4 => CgroupSockAddrAttachType::GetPeerName4,
            Self::GetPeerName6 => CgroupSockAddrAttachType::GetPeerName6,
            Self::GetSockName4 => CgroupSockAddrAttachType::GetSockName4,
            Self::GetSockName6 => CgroupSockAddrAttachType::GetSockName6,
            Self::SendMsg4 => CgroupSockAddrAttachType::UDPSendMsg4,
            Self::SendMsg6 => CgroupSockAddrAttachType::UDPSendMsg6,
            Self::RecvMsg4 => CgroupSockAddrAttachType::UDPRecvMsg4,
            Self::RecvMsg6 => CgroupSockAddrAttachType::UDPRecvMsg6,
            Self::ConnectUnix
            | Self::GetPeerNameUnix
            | Self::GetSockNameUnix
            | Self::SendMsgUnix
            | Self::RecvMsgUnix => return None,
        })
    }

    pub(crate) fn address_family(self) -> ProgramAttachAddressFamily {
        match self {
            Self::Bind4
            | Self::Connect4
            | Self::GetPeerName4
            | Self::GetSockName4
            | Self::SendMsg4
            | Self::RecvMsg4 => ProgramAttachAddressFamily::Ipv4,
            Self::Bind6
            | Self::Connect6
            | Self::GetPeerName6
            | Self::GetSockName6
            | Self::SendMsg6
            | Self::RecvMsg6 => ProgramAttachAddressFamily::Ipv6,
            Self::ConnectUnix
            | Self::GetPeerNameUnix
            | Self::GetSockNameUnix
            | Self::SendMsgUnix
            | Self::RecvMsgUnix => ProgramAttachAddressFamily::Unix,
        }
    }

    pub(crate) fn hook_kind(self) -> ProgramAttachSockAddrHook {
        match self {
            Self::Bind4 | Self::Bind6 => ProgramAttachSockAddrHook::Bind,
            Self::Connect4 | Self::Connect6 | Self::ConnectUnix => {
                ProgramAttachSockAddrHook::Connect
            }
            Self::GetPeerName4 | Self::GetPeerName6 | Self::GetPeerNameUnix => {
                ProgramAttachSockAddrHook::GetPeerName
            }
            Self::GetSockName4 | Self::GetSockName6 | Self::GetSockNameUnix => {
                ProgramAttachSockAddrHook::GetSockName
            }
            Self::SendMsg4 | Self::SendMsg6 | Self::SendMsgUnix => {
                ProgramAttachSockAddrHook::SendMsg
            }
            Self::RecvMsg4 | Self::RecvMsg6 | Self::RecvMsgUnix => {
                ProgramAttachSockAddrHook::RecvMsg
            }
        }
    }
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

        let attach_type = CgroupSockAddrAttachKind::parse(attach_kind).ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid cgroup_sock_addr attach kind: {attach_kind}. Expected one of bind4, bind6, connect4, connect6, getpeername4, getpeername6, getsockname4, getsockname6, sendmsg4, sendmsg6, recvmsg4, recvmsg6, connect_unix, getpeername_unix, getsockname_unix, sendmsg_unix, recvmsg_unix"
            ))
        })?;

        Ok(Self {
            cgroup_path: cgroup_path.to_string(),
            attach_type,
        })
    }

    pub fn attach_type_name(&self) -> &'static str {
        self.attach_type.name()
    }

    pub fn target_string(&self) -> String {
        format!("{}:{}", self.cgroup_path, self.attach_type_name())
    }

    pub fn section_name(&self) -> String {
        format!("cgroup/{}", self.attach_type_name())
    }

    pub fn is_ipv4(&self) -> bool {
        self.attach_type.address_family() == ProgramAttachAddressFamily::Ipv4
    }

    pub fn is_ipv6(&self) -> bool {
        self.attach_type.address_family() == ProgramAttachAddressFamily::Ipv6
    }

    pub fn is_unix(&self) -> bool {
        self.attach_type.address_family() == ProgramAttachAddressFamily::Unix
    }

    pub fn aya_attach_type(&self) -> Option<CgroupSockAddrAttachType> {
        self.attach_type.aya_attach_type()
    }

    pub(crate) fn hook_kind(&self) -> ProgramAttachSockAddrHook {
        self.attach_type.hook_kind()
    }

    pub fn supports_msg_source(&self) -> bool {
        self.hook_kind().is_sendmsg()
    }

    pub fn is_connect(&self) -> bool {
        self.hook_kind().is_connect()
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

/// Parsed flow_dissector target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDissectorTarget {
    /// Filesystem path to the network namespace file.
    pub netns_path: String,
}

impl FlowDissectorTarget {
    /// Parse a flow_dissector target string of the form `/proc/self/ns/net`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "flow_dissector network namespace path cannot be empty",
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

/// Netfilter protocol families supported by BPF netfilter links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetfilterProtocolFamily {
    Ipv4,
    Ipv6,
}

impl NetfilterProtocolFamily {
    pub fn target_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" | "ipv4" => Some(Self::Ipv4),
            "ip6" | "ipv6" => Some(Self::Ipv6),
            _ => None,
        }
    }
}

/// Netfilter hook numbers supported by BPF netfilter links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetfilterHook {
    PreRouting,
    LocalIn,
    Forward,
    LocalOut,
    PostRouting,
}

impl NetfilterHook {
    pub fn target_name(self) -> &'static str {
        match self {
            Self::PreRouting => "pre_routing",
            Self::LocalIn => "local_in",
            Self::Forward => "forward",
            Self::LocalOut => "local_out",
            Self::PostRouting => "post_routing",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "prerouting" | "pre_routing" => Some(Self::PreRouting),
            "localin" | "local_in" => Some(Self::LocalIn),
            "forward" => Some(Self::Forward),
            "localout" | "local_out" => Some(Self::LocalOut),
            "postrouting" | "post_routing" => Some(Self::PostRouting),
            _ => None,
        }
    }
}

/// Parsed netfilter target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetfilterTarget {
    /// Protocol family passed to BPF link netfilter attach.
    pub family: NetfilterProtocolFamily,
    /// Netfilter hook number passed to BPF link netfilter attach.
    pub hook: NetfilterHook,
    /// Hook priority. Defaults to `0`.
    pub priority: i32,
    /// Request kernel IP defragmentation before the BPF hook.
    pub defrag: bool,
}

impl NetfilterTarget {
    /// Parse `family:hook[:priority=N][:defrag]`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let mut parts = target.split(':');
        let family_part = parts.next().unwrap_or_default();
        let hook_part = parts.next().unwrap_or_default();

        let family = NetfilterProtocolFamily::parse(family_part).ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid netfilter family: {family_part}. Expected ipv4 or ipv6"
            ))
        })?;
        let hook = NetfilterHook::parse(hook_part).ok_or_else(|| {
            ProgramSpecParseError::new(format!(
                "Invalid netfilter hook: {hook_part}. Expected pre_routing, local_in, forward, local_out, or post_routing"
            ))
        })?;

        let mut priority = 0;
        let mut defrag = false;
        for option in parts {
            if option == "defrag" {
                defrag = true;
                continue;
            }
            if let Some(value) = option.strip_prefix("priority=") {
                priority = value.parse().map_err(|_| {
                    ProgramSpecParseError::new(format!(
                        "Invalid netfilter priority: {value}. Expected a signed integer"
                    ))
                })?;
                continue;
            }
            if let Some(value) = option.strip_prefix("prio=") {
                priority = value.parse().map_err(|_| {
                    ProgramSpecParseError::new(format!(
                        "Invalid netfilter priority: {value}. Expected a signed integer"
                    ))
                })?;
                continue;
            }

            return Err(ProgramSpecParseError::new(format!(
                "Unrecognized netfilter option: {option}. Expected priority=N, prio=N, or defrag"
            )));
        }

        if defrag && priority <= -400 {
            return Err(ProgramSpecParseError::new(
                "Invalid netfilter target: defrag requires priority greater than -400",
            ));
        }

        Ok(Self {
            family,
            hook,
            priority,
            defrag,
        })
    }

    pub fn target_string(&self) -> String {
        let mut target = format!("{}:{}", self.family.target_name(), self.hook.target_name());
        if self.priority != 0 {
            target.push_str(&format!(":priority={}", self.priority));
        }
        if self.defrag {
            target.push_str(":defrag");
        }
        target
    }
}

/// Parsed lightweight tunnel target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwtTarget {
    /// Descriptive route/attachment label. Live route attach is not implemented yet.
    pub route: String,
}

impl LwtTarget {
    /// Parse an LWT target label. The current compiler uses it for metadata only.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "lwt target label cannot be empty",
            ));
        }

        Ok(Self {
            route: target.to_string(),
        })
    }

    pub fn target_string(&self) -> String {
        self.route.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramAttachLwtHook {
    In,
    Out,
    Xmit,
    Seg6Local,
}

impl ProgramAttachLwtHook {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
            Self::Xmit => "xmit",
            Self::Seg6Local => "seg6local",
        }
    }
}

/// Supported sk_reuseport section modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkReuseportMode {
    Select,
    Migrate,
}

impl SkReuseportMode {
    pub fn target_name(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Migrate => "migrate",
        }
    }

    pub fn section_name(self) -> &'static str {
        match self {
            Self::Select => "sk_reuseport",
            Self::Migrate => "sk_reuseport/migrate",
        }
    }
}

/// Parsed sk_reuseport target information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkReuseportTarget {
    /// Section mode. `select` is the default reuseport selector surface.
    pub mode: SkReuseportMode,
}

impl SkReuseportTarget {
    /// Parse a sk_reuseport target string of the form `select` or `migrate`.
    pub fn parse(target: &str) -> Result<Self, ProgramSpecParseError> {
        let mode = match target {
            "select" | "default" => SkReuseportMode::Select,
            "migrate" => SkReuseportMode::Migrate,
            _ => {
                return Err(ProgramSpecParseError::new(format!(
                    "Invalid sk_reuseport target: {target}. Expected select or migrate"
                )));
            }
        };

        Ok(Self { mode })
    }

    pub fn target_string(&self) -> String {
        self.mode.target_name().to_string()
    }

    pub fn section_name(&self) -> &'static str {
        self.mode.section_name()
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

    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Period(_) => "period",
            Self::Frequency(_) => "freq",
        }
    }

    pub(crate) fn value(self) -> u64 {
        match self {
            Self::Period(value) | Self::Frequency(value) => value,
        }
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
    Kprobe {
        function: String,
    },
    Kretprobe {
        function: String,
    },
    KprobeMulti {
        pattern: String,
    },
    KretprobeMulti {
        pattern: String,
    },
    Ksyscall {
        syscall: String,
    },
    KretSyscall {
        syscall: String,
    },
    Fentry {
        function: String,
        sleepable: bool,
    },
    Fexit {
        function: String,
        sleepable: bool,
    },
    FmodRet {
        function: String,
        sleepable: bool,
    },
    TpBtf {
        name: String,
    },
    Lsm {
        hook: String,
        sleepable: bool,
    },
    LsmCgroup {
        hook: String,
    },
    Extension {
        target: ExtensionTarget,
    },
    Syscall {
        target: SyscallTarget,
    },
    Iter {
        target: IterTarget,
    },
    Tracepoint {
        category: String,
        name: String,
    },
    RawTracepoint {
        name: String,
    },
    RawTracepointWritable {
        name: String,
    },
    Uprobe {
        target: UprobeTarget,
        sleepable: bool,
    },
    Uretprobe {
        target: UprobeTarget,
        sleepable: bool,
    },
    UprobeMulti {
        target: UprobeMultiTarget,
        sleepable: bool,
    },
    UretprobeMulti {
        target: UprobeMultiTarget,
        sleepable: bool,
    },
    Xdp {
        target: XdpTarget,
    },
    PerfEvent {
        target: PerfEventTarget,
    },
    SocketFilter {
        target: SocketFilterTarget,
    },
    SkLookup {
        target: SkLookupTarget,
    },
    FlowDissector {
        target: FlowDissectorTarget,
    },
    Netfilter {
        target: NetfilterTarget,
    },
    LwtIn {
        target: LwtTarget,
    },
    LwtOut {
        target: LwtTarget,
    },
    LwtXmit {
        target: LwtTarget,
    },
    LwtSeg6Local {
        target: LwtTarget,
    },
    SkReuseport {
        target: SkReuseportTarget,
    },
    SkMsg {
        target: SkMsgTarget,
    },
    SkSkb {
        target: SkSkbTarget,
    },
    SkSkbParser {
        target: SkSkbTarget,
    },
    CgroupDevice {
        target: CgroupDeviceTarget,
    },
    SockOps {
        target: SockOpsTarget,
    },
    Tc {
        target: TcTarget,
    },
    Tcx {
        target: TcTarget,
    },
    Netkit {
        target: NetkitTarget,
    },
    TcAction {
        target: TcActionTarget,
    },
    CgroupSkb {
        target: CgroupSkbTarget,
    },
    CgroupSock {
        target: CgroupSockTarget,
    },
    CgroupSysctl {
        target: CgroupSysctlTarget,
    },
    CgroupSockopt {
        target: CgroupSockoptTarget,
    },
    CgroupSockAddr {
        target: CgroupSockAddrTarget,
    },
    LircMode2 {
        target: LircMode2Target,
    },
    StructOps {
        value_type_name: String,
    },
    StructOpsCallback {
        value_type_name: String,
        callback_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramAttachAddressFamily {
    Ipv4,
    Ipv6,
    Unix,
}

impl ProgramAttachAddressFamily {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Unix => "unix",
        }
    }

    pub(crate) fn is_inet(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramAttachSockAddrHook {
    Bind,
    Connect,
    GetPeerName,
    GetSockName,
    SendMsg,
    RecvMsg,
}

impl ProgramAttachSockAddrHook {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Connect => "connect",
            Self::GetPeerName => "getpeername",
            Self::GetSockName => "getsockname",
            Self::SendMsg => "sendmsg",
            Self::RecvMsg => "recvmsg",
        }
    }

    pub(crate) fn is_connect(self) -> bool {
        matches!(self, Self::Connect)
    }

    pub(crate) fn is_sendmsg(self) -> bool {
        matches!(self, Self::SendMsg)
    }

    pub(crate) fn exposes_remote_tuple(self) -> bool {
        matches!(
            self,
            Self::Connect | Self::GetPeerName | Self::SendMsg | Self::RecvMsg
        )
    }

    pub(crate) fn exposes_local_ip_alias(self) -> bool {
        matches!(self, Self::Bind | Self::GetSockName | Self::SendMsg)
    }

    pub(crate) fn exposes_local_tuple(self) -> bool {
        matches!(self, Self::Bind | Self::GetSockName)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramAttachShape {
    Generic,
    Syscall,
    Iter,
    Xdp {
        mode: XdpAttachMode,
        frags: bool,
    },
    PerfEvent {
        event: PerfEventEvent,
        cpu: Option<u32>,
        pid: Option<u32>,
        sample_policy: PerfEventSamplePolicy,
    },
    SocketFilter {
        socket_kind: SocketFilterSocketKind,
    },
    SkLookup,
    FlowDissector,
    SkMsg,
    SkSkb {
        parser: bool,
    },
    Netkit {
        endpoint: NetkitAttachType,
    },
    TcAction,
    SkReuseport {
        mode: SkReuseportMode,
    },
    Lwt {
        hook: ProgramAttachLwtHook,
    },
    Netfilter {
        family: NetfilterProtocolFamily,
        hook: NetfilterHook,
        priority: i32,
        defrag: bool,
    },
    Tc {
        ingress: bool,
    },
    CgroupSkb {
        ingress: bool,
    },
    CgroupDevice,
    CgroupSysctl,
    SockOps,
    CgroupSock {
        post_bind: bool,
        family: Option<ProgramAttachAddressFamily>,
    },
    CgroupSockopt {
        get: bool,
    },
    CgroupSockAddr {
        family: ProgramAttachAddressFamily,
        hook: ProgramAttachSockAddrHook,
    },
    LircMode2,
    StructOps {
        family: StructOpsFamily,
    },
    StructOpsCallback {
        family: StructOpsFamily,
        sleepable: bool,
    },
}

impl ProgramAttachShape {
    pub(crate) fn is_tc_ingress(self) -> bool {
        matches!(self, Self::Tc { ingress: true })
    }

    pub(crate) fn is_tc_egress(self) -> bool {
        matches!(self, Self::Tc { ingress: false })
    }

    pub(crate) fn is_cgroup_skb_ingress(self) -> bool {
        matches!(self, Self::CgroupSkb { ingress: true })
    }

    pub(crate) fn is_cgroup_sock_create_release(self) -> bool {
        matches!(
            self,
            Self::CgroupSock {
                post_bind: false,
                ..
            }
        )
    }

    pub(crate) fn is_cgroup_sock_post_bind(self) -> bool {
        matches!(
            self,
            Self::CgroupSock {
                post_bind: true,
                ..
            }
        )
    }

    pub(crate) fn is_cgroup_sock_post_bind_family(
        self,
        family: ProgramAttachAddressFamily,
    ) -> bool {
        matches!(
            self,
            Self::CgroupSock {
                post_bind: true,
                family: Some(actual),
            } if actual == family
        )
    }

    pub(crate) fn is_cgroup_sock(self) -> bool {
        matches!(self, Self::CgroupSock { .. })
    }

    pub(crate) fn is_cgroup_sockopt_get(self) -> bool {
        matches!(self, Self::CgroupSockopt { get: true })
    }

    pub(crate) fn is_cgroup_sockopt_set(self) -> bool {
        matches!(self, Self::CgroupSockopt { get: false })
    }

    pub(crate) fn is_cgroup_sockopt(self) -> bool {
        matches!(self, Self::CgroupSockopt { .. })
    }

    pub(crate) fn cgroup_sock_addr(
        self,
    ) -> Option<(ProgramAttachAddressFamily, ProgramAttachSockAddrHook)> {
        match self {
            Self::CgroupSockAddr { family, hook } => Some((family, hook)),
            _ => None,
        }
    }

    pub(crate) fn struct_ops_callback(self) -> Option<(StructOpsFamily, bool)> {
        match self {
            Self::StructOpsCallback { family, sleepable } => Some((family, sleepable)),
            _ => None,
        }
    }
}

impl ProgramSpec {
    pub fn representative_target_for_program_type(program_type: EbpfProgramType) -> &'static str {
        match program_type {
            EbpfProgramType::Kprobe => "ksys_read",
            EbpfProgramType::Kretprobe => "ksys_read",
            EbpfProgramType::KprobeMulti => "vfs_*",
            EbpfProgramType::KretprobeMulti => "vfs_*",
            EbpfProgramType::Ksyscall => "nanosleep",
            EbpfProgramType::KretSyscall => "nanosleep",
            EbpfProgramType::Fentry => "vfs_read",
            EbpfProgramType::Fexit => "vfs_read",
            EbpfProgramType::FmodRet => "bpf_modify_return_test",
            EbpfProgramType::TpBtf => "sched_switch",
            EbpfProgramType::Lsm => "file_open",
            EbpfProgramType::LsmCgroup => "socket_bind",
            EbpfProgramType::Extension => "replace_me",
            EbpfProgramType::Syscall => "demo",
            EbpfProgramType::Iter => "task",
            EbpfProgramType::Tracepoint => "syscalls/sys_enter_openat",
            EbpfProgramType::RawTracepoint => "sys_enter",
            EbpfProgramType::RawTracepointWritable => "sys_enter",
            EbpfProgramType::Uprobe => "/bin/bash:main",
            EbpfProgramType::Uretprobe => "/bin/bash:main",
            EbpfProgramType::UprobeMulti => "/bin/bash:read*",
            EbpfProgramType::UretprobeMulti => "/bin/bash:read*",
            EbpfProgramType::Xdp => "lo",
            EbpfProgramType::PerfEvent => "software:cpu-clock:cpu=1",
            EbpfProgramType::SocketFilter => "tcp4:127.0.0.1:8080",
            EbpfProgramType::SkLookup => "/proc/self/ns/net",
            EbpfProgramType::FlowDissector => "/proc/self/ns/net",
            EbpfProgramType::Netfilter => "ipv4:pre_routing:priority=-100:defrag",
            EbpfProgramType::LwtIn
            | EbpfProgramType::LwtOut
            | EbpfProgramType::LwtXmit
            | EbpfProgramType::LwtSeg6Local => "demo-route",
            EbpfProgramType::SkReuseport => "select",
            EbpfProgramType::SkMsg => "/sys/fs/bpf/demo_sockmap",
            EbpfProgramType::SkSkb => "/sys/fs/bpf/demo_sockmap",
            EbpfProgramType::SkSkbParser => "/sys/fs/bpf/demo_sockmap",
            EbpfProgramType::CgroupDevice => "/sys/fs/cgroup",
            EbpfProgramType::SockOps => "/sys/fs/cgroup",
            EbpfProgramType::Tc => "lo:ingress",
            EbpfProgramType::Tcx => "lo:ingress",
            EbpfProgramType::Netkit => "nk0:primary",
            EbpfProgramType::TcAction => "demo-action",
            EbpfProgramType::CgroupSkb => "/sys/fs/cgroup:egress",
            EbpfProgramType::CgroupSock => "/sys/fs/cgroup:sock_create",
            EbpfProgramType::CgroupSysctl => "/sys/fs/cgroup",
            EbpfProgramType::CgroupSockopt => "/sys/fs/cgroup:get",
            EbpfProgramType::CgroupSockAddr => "/sys/fs/cgroup:connect4",
            EbpfProgramType::LircMode2 => "/dev/lirc0",
            EbpfProgramType::StructOps => "sched_ext_ops",
        }
    }

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

        Self::from_program_type_target_with_sleepable(
            prog_type,
            target,
            matches!(
                prefix,
                "fentry.s"
                    | "fexit.s"
                    | "fmod_ret.s"
                    | "lsm.s"
                    | "uprobe.s"
                    | "uretprobe.s"
                    | "uprobe.multi.s"
                    | "uretprobe.multi.s"
            ),
        )
    }

    /// Parse a full `type:target` string only when it names the requested program type.
    pub fn parse_matching_program_type(spec: &str, prog_type: EbpfProgramType) -> Option<Self> {
        Self::parse(spec)
            .ok()
            .filter(|program_spec| program_spec.program_type() == prog_type)
    }

    pub fn from_program_type_target(
        prog_type: EbpfProgramType,
        target: &str,
    ) -> Result<Self, ProgramSpecParseError> {
        Self::from_program_type_target_with_sleepable(prog_type, target, false)
    }

    fn from_program_type_target_with_sleepable(
        prog_type: EbpfProgramType,
        target: &str,
        sleepable: bool,
    ) -> Result<Self, ProgramSpecParseError> {
        match prog_type {
            EbpfProgramType::Kprobe => Ok(ProgramSpec::Kprobe {
                function: target.to_string(),
            }),
            EbpfProgramType::Kretprobe => Ok(ProgramSpec::Kretprobe {
                function: target.to_string(),
            }),
            EbpfProgramType::KprobeMulti => Ok(ProgramSpec::KprobeMulti {
                pattern: target.to_string(),
            }),
            EbpfProgramType::KretprobeMulti => Ok(ProgramSpec::KretprobeMulti {
                pattern: target.to_string(),
            }),
            EbpfProgramType::Ksyscall => Ok(ProgramSpec::Ksyscall {
                syscall: target.to_string(),
            }),
            EbpfProgramType::KretSyscall => Ok(ProgramSpec::KretSyscall {
                syscall: target.to_string(),
            }),
            EbpfProgramType::Fentry => Ok(ProgramSpec::Fentry {
                function: target.to_string(),
                sleepable,
            }),
            EbpfProgramType::Fexit => Ok(ProgramSpec::Fexit {
                function: target.to_string(),
                sleepable,
            }),
            EbpfProgramType::FmodRet => Ok(ProgramSpec::FmodRet {
                function: target.to_string(),
                sleepable,
            }),
            EbpfProgramType::TpBtf => Ok(ProgramSpec::TpBtf {
                name: target.to_string(),
            }),
            EbpfProgramType::Lsm => Ok(ProgramSpec::Lsm {
                hook: target.to_string(),
                sleepable,
            }),
            EbpfProgramType::LsmCgroup => Ok(ProgramSpec::LsmCgroup {
                hook: target.to_string(),
            }),
            EbpfProgramType::Extension => Ok(ProgramSpec::Extension {
                target: ExtensionTarget::parse(target)?,
            }),
            EbpfProgramType::Syscall => Ok(ProgramSpec::Syscall {
                target: SyscallTarget::parse(target)?,
            }),
            EbpfProgramType::Iter => Ok(ProgramSpec::Iter {
                target: IterTarget::parse(target)?,
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
            EbpfProgramType::RawTracepointWritable => Ok(ProgramSpec::RawTracepointWritable {
                name: target.to_string(),
            }),
            EbpfProgramType::Uprobe => Ok(ProgramSpec::Uprobe {
                target: UprobeTarget::parse(target)?,
                sleepable,
            }),
            EbpfProgramType::Uretprobe => Ok(ProgramSpec::Uretprobe {
                target: UprobeTarget::parse(target)?,
                sleepable,
            }),
            EbpfProgramType::UprobeMulti => Ok(ProgramSpec::UprobeMulti {
                target: UprobeMultiTarget::parse(target)?,
                sleepable,
            }),
            EbpfProgramType::UretprobeMulti => Ok(ProgramSpec::UretprobeMulti {
                target: UprobeMultiTarget::parse(target)?,
                sleepable,
            }),
            EbpfProgramType::Xdp => Ok(ProgramSpec::Xdp {
                target: XdpTarget::parse(target)?,
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
            EbpfProgramType::FlowDissector => Ok(ProgramSpec::FlowDissector {
                target: FlowDissectorTarget::parse(target)?,
            }),
            EbpfProgramType::Netfilter => Ok(ProgramSpec::Netfilter {
                target: NetfilterTarget::parse(target)?,
            }),
            EbpfProgramType::LwtIn => Ok(ProgramSpec::LwtIn {
                target: LwtTarget::parse(target)?,
            }),
            EbpfProgramType::LwtOut => Ok(ProgramSpec::LwtOut {
                target: LwtTarget::parse(target)?,
            }),
            EbpfProgramType::LwtXmit => Ok(ProgramSpec::LwtXmit {
                target: LwtTarget::parse(target)?,
            }),
            EbpfProgramType::LwtSeg6Local => Ok(ProgramSpec::LwtSeg6Local {
                target: LwtTarget::parse(target)?,
            }),
            EbpfProgramType::SkReuseport => Ok(ProgramSpec::SkReuseport {
                target: SkReuseportTarget::parse(target)?,
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
            EbpfProgramType::Tcx => Ok(ProgramSpec::Tcx {
                target: TcTarget::parse(target)?,
            }),
            EbpfProgramType::Netkit => Ok(ProgramSpec::Netkit {
                target: NetkitTarget::parse(target)?,
            }),
            EbpfProgramType::TcAction => Ok(ProgramSpec::TcAction {
                target: TcActionTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSkb => Ok(ProgramSpec::CgroupSkb {
                target: CgroupSkbTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSock => Ok(ProgramSpec::CgroupSock {
                target: CgroupSockTarget::parse(target)?,
            }),
            EbpfProgramType::CgroupSysctl => Ok(ProgramSpec::CgroupSysctl {
                target: CgroupSysctlTarget::parse(target)?,
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
            EbpfProgramType::StructOps => Self::from_struct_ops_target(target),
        }
    }

    fn from_struct_ops_target(target: &str) -> Result<Self, ProgramSpecParseError> {
        if target.is_empty() {
            return Err(ProgramSpecParseError::new(
                "struct_ops target requires a value type name",
            ));
        }

        if let Some((value_type_name, callback_name)) = target.rsplit_once('.') {
            if value_type_name.is_empty() {
                return Err(ProgramSpecParseError::new(
                    "struct_ops callback target requires a value type name before '.'",
                ));
            }
            if callback_name.is_empty() {
                return Err(ProgramSpecParseError::new(
                    "struct_ops callback target requires a callback name after '.'",
                ));
            }
            return Ok(ProgramSpec::StructOpsCallback {
                value_type_name: value_type_name.to_string(),
                callback_name: callback_name.to_string(),
            });
        }

        Ok(ProgramSpec::StructOps {
            value_type_name: target.to_string(),
        })
    }

    pub fn program_type(&self) -> EbpfProgramType {
        match self {
            ProgramSpec::Kprobe { .. } => EbpfProgramType::Kprobe,
            ProgramSpec::Kretprobe { .. } => EbpfProgramType::Kretprobe,
            ProgramSpec::KprobeMulti { .. } => EbpfProgramType::KprobeMulti,
            ProgramSpec::KretprobeMulti { .. } => EbpfProgramType::KretprobeMulti,
            ProgramSpec::Ksyscall { .. } => EbpfProgramType::Ksyscall,
            ProgramSpec::KretSyscall { .. } => EbpfProgramType::KretSyscall,
            ProgramSpec::Fentry { .. } => EbpfProgramType::Fentry,
            ProgramSpec::Fexit { .. } => EbpfProgramType::Fexit,
            ProgramSpec::FmodRet { .. } => EbpfProgramType::FmodRet,
            ProgramSpec::TpBtf { .. } => EbpfProgramType::TpBtf,
            ProgramSpec::Lsm { .. } => EbpfProgramType::Lsm,
            ProgramSpec::LsmCgroup { .. } => EbpfProgramType::LsmCgroup,
            ProgramSpec::Extension { .. } => EbpfProgramType::Extension,
            ProgramSpec::Syscall { .. } => EbpfProgramType::Syscall,
            ProgramSpec::Iter { .. } => EbpfProgramType::Iter,
            ProgramSpec::Tracepoint { .. } => EbpfProgramType::Tracepoint,
            ProgramSpec::RawTracepoint { .. } => EbpfProgramType::RawTracepoint,
            ProgramSpec::RawTracepointWritable { .. } => EbpfProgramType::RawTracepointWritable,
            ProgramSpec::Uprobe { .. } => EbpfProgramType::Uprobe,
            ProgramSpec::Uretprobe { .. } => EbpfProgramType::Uretprobe,
            ProgramSpec::UprobeMulti { .. } => EbpfProgramType::UprobeMulti,
            ProgramSpec::UretprobeMulti { .. } => EbpfProgramType::UretprobeMulti,
            ProgramSpec::Xdp { .. } => EbpfProgramType::Xdp,
            ProgramSpec::PerfEvent { .. } => EbpfProgramType::PerfEvent,
            ProgramSpec::SocketFilter { .. } => EbpfProgramType::SocketFilter,
            ProgramSpec::SkLookup { .. } => EbpfProgramType::SkLookup,
            ProgramSpec::FlowDissector { .. } => EbpfProgramType::FlowDissector,
            ProgramSpec::Netfilter { .. } => EbpfProgramType::Netfilter,
            ProgramSpec::LwtIn { .. } => EbpfProgramType::LwtIn,
            ProgramSpec::LwtOut { .. } => EbpfProgramType::LwtOut,
            ProgramSpec::LwtXmit { .. } => EbpfProgramType::LwtXmit,
            ProgramSpec::LwtSeg6Local { .. } => EbpfProgramType::LwtSeg6Local,
            ProgramSpec::SkReuseport { .. } => EbpfProgramType::SkReuseport,
            ProgramSpec::SkMsg { .. } => EbpfProgramType::SkMsg,
            ProgramSpec::SkSkb { .. } => EbpfProgramType::SkSkb,
            ProgramSpec::SkSkbParser { .. } => EbpfProgramType::SkSkbParser,
            ProgramSpec::CgroupDevice { .. } => EbpfProgramType::CgroupDevice,
            ProgramSpec::SockOps { .. } => EbpfProgramType::SockOps,
            ProgramSpec::Tc { .. } => EbpfProgramType::Tc,
            ProgramSpec::Tcx { .. } => EbpfProgramType::Tcx,
            ProgramSpec::Netkit { .. } => EbpfProgramType::Netkit,
            ProgramSpec::TcAction { .. } => EbpfProgramType::TcAction,
            ProgramSpec::CgroupSkb { .. } => EbpfProgramType::CgroupSkb,
            ProgramSpec::CgroupSock { .. } => EbpfProgramType::CgroupSock,
            ProgramSpec::CgroupSysctl { .. } => EbpfProgramType::CgroupSysctl,
            ProgramSpec::CgroupSockopt { .. } => EbpfProgramType::CgroupSockopt,
            ProgramSpec::CgroupSockAddr { .. } => EbpfProgramType::CgroupSockAddr,
            ProgramSpec::LircMode2 { .. } => EbpfProgramType::LircMode2,
            ProgramSpec::StructOps { .. } | ProgramSpec::StructOpsCallback { .. } => {
                EbpfProgramType::StructOps
            }
        }
    }

    pub fn compatibility_requirements(&self) -> Vec<ProgramCompatibilityRequirement> {
        let mut requirements = self.program_type().compatibility_requirements().to_vec();

        match self {
            ProgramSpec::Fentry {
                sleepable: true, ..
            }
            | ProgramSpec::Fexit {
                sleepable: true, ..
            }
            | ProgramSpec::FmodRet {
                sleepable: true, ..
            }
            | ProgramSpec::Lsm {
                sleepable: true, ..
            }
            | ProgramSpec::Uprobe {
                sleepable: true, ..
            }
            | ProgramSpec::Uretprobe {
                sleepable: true, ..
            }
            | ProgramSpec::UprobeMulti {
                sleepable: true, ..
            }
            | ProgramSpec::UretprobeMulti {
                sleepable: true, ..
            } => push_compatibility_requirement(
                &mut requirements,
                ProgramCompatibilityRequirement::SleepableProgram,
            ),
            ProgramSpec::StructOpsCallback {
                value_type_name,
                callback_name,
            } if struct_ops_callback_is_sleepable(value_type_name, callback_name) => {
                push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::SleepableProgram,
                );
            }
            _ => {}
        }

        if let ProgramSpec::Xdp { target } = self {
            let attach_requirement = match target.attach_mode {
                XdpAttachMode::Skb => ProgramCompatibilityRequirement::XdpSkbAttachMode,
                XdpAttachMode::Driver => ProgramCompatibilityRequirement::XdpDrvAttachMode,
                XdpAttachMode::Hardware => ProgramCompatibilityRequirement::XdpHwAttachMode,
            };
            push_compatibility_requirement(&mut requirements, attach_requirement);
            if target.frags {
                push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::XdpMultiBuffer,
                );
            }
        }

        if let Some(value_type_name) = self.struct_ops_value_type_name() {
            match StructOpsFamily::from_value_type_name(value_type_name) {
                StructOpsFamily::TcpCongestion => push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::TcpCongestionOps,
                ),
                StructOpsFamily::HidBpf => push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::HidBpfOps,
                ),
                StructOpsFamily::SchedExt => push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::SchedExt,
                ),
                StructOpsFamily::Qdisc => push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::QdiscOps,
                ),
                StructOpsFamily::Generic => {}
            }
        }

        if let ProgramSpec::CgroupSockAddr { target } = self {
            if target.attach_type.address_family() == ProgramAttachAddressFamily::Unix {
                push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::CgroupUnixSockAddr,
                );
            }
        }

        if let ProgramSpec::SkReuseport { target } = self {
            if target.mode == SkReuseportMode::Migrate {
                push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::SkReuseportMigration,
                );
            }
        }

        if let ProgramSpec::Netfilter { target } = self {
            if target.defrag {
                push_compatibility_requirement(
                    &mut requirements,
                    ProgramCompatibilityRequirement::NetfilterDefrag,
                );
            }
        }

        if let ProgramSpec::Iter { target } = self {
            if let Some(requirement) = iterator_target_compatibility_requirement(&target.name) {
                push_compatibility_requirement(&mut requirements, requirement);
            }
        }

        requirements
    }

    pub fn requires_compatibility_feature(
        &self,
        requirement: ProgramCompatibilityRequirement,
    ) -> bool {
        self.compatibility_requirements().contains(&requirement)
    }

    pub fn sleepable(&self) -> bool {
        match self {
            ProgramSpec::Fentry {
                sleepable: true, ..
            }
            | ProgramSpec::Fexit {
                sleepable: true, ..
            }
            | ProgramSpec::FmodRet {
                sleepable: true, ..
            }
            | ProgramSpec::Lsm {
                sleepable: true, ..
            }
            | ProgramSpec::Uprobe {
                sleepable: true, ..
            }
            | ProgramSpec::Uretprobe {
                sleepable: true, ..
            }
            | ProgramSpec::UprobeMulti {
                sleepable: true, ..
            }
            | ProgramSpec::UretprobeMulti {
                sleepable: true, ..
            } => true,
            ProgramSpec::StructOpsCallback {
                value_type_name,
                callback_name,
            } => struct_ops_callback_is_sleepable(value_type_name, callback_name),
            _ => false,
        }
    }

    pub fn live_attach_policy(&self) -> ProgramLiveAttachPolicy {
        if let ProgramSpec::CgroupSockAddr { target } = self {
            if target.is_unix() {
                return ProgramLiveAttachPolicy::unsupported(
                    CGROUP_SOCK_ADDR_UNIX_LIVE_ATTACH_UNSUPPORTED,
                );
            }
        }

        let risk = self
            .struct_ops_value_type_name()
            .and_then(|value_type_name| {
                StructOpsFamily::from_value_type_name(value_type_name).live_attach_risk()
            });
        ProgramLiveAttachPolicy::from_attach_kind_and_risk(self.program_type().attach_kind(), risk)
    }

    pub fn target_string(&self) -> String {
        match self {
            ProgramSpec::Kprobe { function }
            | ProgramSpec::Kretprobe { function }
            | ProgramSpec::Fentry { function, .. }
            | ProgramSpec::Fexit { function, .. }
            | ProgramSpec::FmodRet { function, .. } => function.clone(),
            ProgramSpec::KprobeMulti { pattern } | ProgramSpec::KretprobeMulti { pattern } => {
                pattern.clone()
            }
            ProgramSpec::Ksyscall { syscall } | ProgramSpec::KretSyscall { syscall } => {
                syscall.clone()
            }
            ProgramSpec::TpBtf { name } => name.clone(),
            ProgramSpec::Lsm { hook, .. } => hook.clone(),
            ProgramSpec::LsmCgroup { hook } => hook.clone(),
            ProgramSpec::Extension { target } => target.target_string(),
            ProgramSpec::Syscall { target } => target.target_string(),
            ProgramSpec::Iter { target } => target.target_string(),
            ProgramSpec::Tracepoint { category, name } => format!("{category}/{name}"),
            ProgramSpec::RawTracepoint { name } => name.clone(),
            ProgramSpec::RawTracepointWritable { name } => name.clone(),
            ProgramSpec::Uprobe { target, .. } | ProgramSpec::Uretprobe { target, .. } => {
                target.target_string()
            }
            ProgramSpec::UprobeMulti { target, .. }
            | ProgramSpec::UretprobeMulti { target, .. } => target.target_string(),
            ProgramSpec::Xdp { target } => target.target_string(),
            ProgramSpec::PerfEvent { target } => target.target_string(),
            ProgramSpec::SocketFilter { target } => target.target_string(),
            ProgramSpec::SkLookup { target } => target.target_string(),
            ProgramSpec::FlowDissector { target } => target.target_string(),
            ProgramSpec::Netfilter { target } => target.target_string(),
            ProgramSpec::LwtIn { target }
            | ProgramSpec::LwtOut { target }
            | ProgramSpec::LwtXmit { target }
            | ProgramSpec::LwtSeg6Local { target } => target.target_string(),
            ProgramSpec::SkReuseport { target } => target.target_string(),
            ProgramSpec::SkMsg { target } => target.target_string(),
            ProgramSpec::SkSkb { target } => target.target_string(),
            ProgramSpec::SkSkbParser { target } => target.target_string(),
            ProgramSpec::CgroupDevice { target } => target.target_string(),
            ProgramSpec::SockOps { target } => target.target_string(),
            ProgramSpec::Tc { target } => target.target_string(),
            ProgramSpec::Tcx { target } => target.target_string(),
            ProgramSpec::Netkit { target } => target.target_string(),
            ProgramSpec::TcAction { target } => target.target_string(),
            ProgramSpec::CgroupSkb { target } => target.target_string(),
            ProgramSpec::CgroupSock { target } => target.target_string(),
            ProgramSpec::CgroupSysctl { target } => target.target_string(),
            ProgramSpec::CgroupSockopt { target } => target.target_string(),
            ProgramSpec::CgroupSockAddr { target } => target.target_string(),
            ProgramSpec::LircMode2 { target } => target.target_string(),
            ProgramSpec::StructOps { value_type_name } => value_type_name.clone(),
            ProgramSpec::StructOpsCallback { callback_name, .. } => callback_name.clone(),
        }
    }

    pub(crate) fn tracepoint_parts(&self) -> Option<(&str, &str)> {
        match self {
            ProgramSpec::Tracepoint { category, name } => Some((category, name)),
            _ => None,
        }
    }

    pub(crate) fn uprobe_target(&self) -> Option<&UprobeTarget> {
        match self {
            ProgramSpec::Uprobe { target, .. } | ProgramSpec::Uretprobe { target, .. } => {
                Some(target)
            }
            _ => None,
        }
    }

    pub(crate) fn uprobe_multi_target(&self) -> Option<&UprobeMultiTarget> {
        match self {
            ProgramSpec::UprobeMulti { target, .. }
            | ProgramSpec::UretprobeMulti { target, .. } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn xdp_target(&self) -> Option<&XdpTarget> {
        match self {
            ProgramSpec::Xdp { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn perf_event_target(&self) -> Option<&PerfEventTarget> {
        match self {
            ProgramSpec::PerfEvent { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn socket_filter_target(&self) -> Option<&SocketFilterTarget> {
        match self {
            ProgramSpec::SocketFilter { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn sk_lookup_target(&self) -> Option<&SkLookupTarget> {
        match self {
            ProgramSpec::SkLookup { target } => Some(target),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn netfilter_target(&self) -> Option<&NetfilterTarget> {
        match self {
            ProgramSpec::Netfilter { target } => Some(target),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn lwt_target(&self) -> Option<&LwtTarget> {
        match self {
            ProgramSpec::LwtIn { target }
            | ProgramSpec::LwtOut { target }
            | ProgramSpec::LwtXmit { target }
            | ProgramSpec::LwtSeg6Local { target } => Some(target),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn flow_dissector_target(&self) -> Option<&FlowDissectorTarget> {
        match self {
            ProgramSpec::FlowDissector { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn lirc_mode2_target(&self) -> Option<&LircMode2Target> {
        match self {
            ProgramSpec::LircMode2 { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn tc_target(&self) -> Option<&TcTarget> {
        match self {
            ProgramSpec::Tc { target } | ProgramSpec::Tcx { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn netkit_target(&self) -> Option<&NetkitTarget> {
        match self {
            ProgramSpec::Netkit { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn cgroup_skb_target(&self) -> Option<&CgroupSkbTarget> {
        match self {
            ProgramSpec::CgroupSkb { target } => Some(target),
            _ => None,
        }
    }

    pub(crate) fn struct_ops_value_type_name(&self) -> Option<&str> {
        match self {
            ProgramSpec::StructOps { value_type_name }
            | ProgramSpec::StructOpsCallback {
                value_type_name, ..
            } => Some(value_type_name),
            _ => None,
        }
    }

    pub(crate) fn struct_ops_callback_name(&self) -> Option<&str> {
        match self {
            ProgramSpec::StructOpsCallback { callback_name, .. } => Some(callback_name),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn struct_ops_family(&self) -> Option<StructOpsFamily> {
        self.struct_ops_value_type_name()
            .map(StructOpsFamily::from_value_type_name)
    }

    pub(crate) fn cgroup_path(&self) -> Option<&str> {
        match self {
            ProgramSpec::CgroupDevice { target } => Some(&target.cgroup_path),
            ProgramSpec::SockOps { target } => Some(&target.cgroup_path),
            ProgramSpec::CgroupSkb { target } => Some(&target.cgroup_path),
            ProgramSpec::CgroupSock { target } => Some(&target.cgroup_path),
            ProgramSpec::CgroupSysctl { target } => Some(&target.cgroup_path),
            ProgramSpec::CgroupSockopt { target } => Some(&target.cgroup_path),
            ProgramSpec::CgroupSockAddr { target } => Some(&target.cgroup_path),
            _ => None,
        }
    }

    pub(crate) fn pinned_map_path(&self) -> Option<&str> {
        match self {
            ProgramSpec::SkMsg { target } => Some(&target.map_path),
            ProgramSpec::SkSkb { target } => Some(&target.map_path),
            ProgramSpec::SkSkbParser { target } => Some(&target.map_path),
            _ => None,
        }
    }

    pub(crate) fn target_kind(&self) -> ProgramTargetKind {
        match self {
            ProgramSpec::StructOps { .. } => ProgramTargetKind::StructOpsValueType,
            ProgramSpec::StructOpsCallback { .. } => ProgramTargetKind::StructOpsCallback,
            _ => self.program_type().target_kind(),
        }
    }

    pub(crate) fn btf_callable_surface(&self) -> Option<ProgramBtfCallableSurface> {
        match self {
            ProgramSpec::StructOps { .. } => None,
            _ => self.program_type().btf_callable_surface(),
        }
    }

    pub(crate) fn arg_access(&self) -> ProgramValueAccess {
        match self {
            ProgramSpec::StructOps { .. } => ProgramValueAccess::None,
            _ => self.program_type().arg_access(),
        }
    }

    pub(crate) fn retval_access(&self) -> ProgramValueAccess {
        match self {
            ProgramSpec::StructOps { .. } => ProgramValueAccess::None,
            _ => self.program_type().retval_access(),
        }
    }

    pub fn section_name(&self) -> String {
        match self {
            ProgramSpec::Fentry {
                function,
                sleepable: true,
            } => format!("fentry.s/{function}"),
            ProgramSpec::Fexit {
                function,
                sleepable: true,
            } => format!("fexit.s/{function}"),
            ProgramSpec::FmodRet {
                function,
                sleepable: true,
            } => format!("fmod_ret.s/{function}"),
            ProgramSpec::Lsm {
                hook,
                sleepable: true,
            } => format!("lsm.s/{hook}"),
            ProgramSpec::Uprobe {
                target,
                sleepable: true,
            } => format!("uprobe.s/{}", target.target_string()),
            ProgramSpec::Uretprobe {
                target,
                sleepable: true,
            } => format!("uretprobe.s/{}", target.target_string()),
            ProgramSpec::UprobeMulti {
                target,
                sleepable: true,
            } => format!("uprobe.multi.s/{}", target.target_string()),
            ProgramSpec::UretprobeMulti {
                target,
                sleepable: true,
            } => format!("uretprobe.multi.s/{}", target.target_string()),
            ProgramSpec::CgroupSkb { target } => target.section_name(),
            ProgramSpec::CgroupSock { target } => target.section_name(),
            ProgramSpec::CgroupSysctl { target } => target.section_name().to_string(),
            ProgramSpec::CgroupSockopt { target } => target.section_name().to_string(),
            ProgramSpec::CgroupSockAddr { target } => target.section_name(),
            ProgramSpec::CgroupDevice { target } => target.section_name().to_string(),
            ProgramSpec::Xdp { target } => target.section_name().to_string(),
            ProgramSpec::Tcx { target } => format!("tcx/{}", target.attach_type_name()),
            ProgramSpec::Netkit { target } => target.section_name(),
            ProgramSpec::SkReuseport { target } => target.section_name().to_string(),
            ProgramSpec::StructOpsCallback { callback_name, .. } => {
                let sleepable = self
                    .attach_shape()
                    .struct_ops_callback()
                    .is_some_and(|(_, sleepable)| sleepable);
                if sleepable {
                    format!("struct_ops.s/{callback_name}")
                } else {
                    format!("struct_ops/{callback_name}")
                }
            }
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

    pub(crate) fn attach_shape(&self) -> ProgramAttachShape {
        match self {
            ProgramSpec::Syscall { .. } => ProgramAttachShape::Syscall,
            ProgramSpec::Iter { .. } => ProgramAttachShape::Iter,
            ProgramSpec::Xdp { target } => ProgramAttachShape::Xdp {
                mode: target.attach_mode,
                frags: target.frags,
            },
            ProgramSpec::PerfEvent { target } => ProgramAttachShape::PerfEvent {
                event: target.event,
                cpu: target.cpu,
                pid: target.pid,
                sample_policy: target.sample_policy,
            },
            ProgramSpec::SocketFilter { target } => ProgramAttachShape::SocketFilter {
                socket_kind: target.socket_kind,
            },
            ProgramSpec::SkLookup { .. } => ProgramAttachShape::SkLookup,
            ProgramSpec::FlowDissector { .. } => ProgramAttachShape::FlowDissector,
            ProgramSpec::SkMsg { .. } => ProgramAttachShape::SkMsg,
            ProgramSpec::SkSkb { .. } => ProgramAttachShape::SkSkb { parser: false },
            ProgramSpec::SkSkbParser { .. } => ProgramAttachShape::SkSkb { parser: true },
            ProgramSpec::Tc { target } | ProgramSpec::Tcx { target } => ProgramAttachShape::Tc {
                ingress: target.is_ingress(),
            },
            ProgramSpec::TcAction { .. } => ProgramAttachShape::TcAction,
            ProgramSpec::CgroupSkb { target } => ProgramAttachShape::CgroupSkb {
                ingress: target.is_ingress(),
            },
            ProgramSpec::CgroupDevice { .. } => ProgramAttachShape::CgroupDevice,
            ProgramSpec::CgroupSysctl { .. } => ProgramAttachShape::CgroupSysctl,
            ProgramSpec::SockOps { .. } => ProgramAttachShape::SockOps,
            ProgramSpec::CgroupSock { target } => ProgramAttachShape::CgroupSock {
                post_bind: target.is_post_bind(),
                family: match target.attach_type {
                    CgroupSockAttachType::PostBind4 => Some(ProgramAttachAddressFamily::Ipv4),
                    CgroupSockAttachType::PostBind6 => Some(ProgramAttachAddressFamily::Ipv6),
                    CgroupSockAttachType::SockCreate | CgroupSockAttachType::SockRelease => None,
                },
            },
            ProgramSpec::CgroupSockopt { target } => ProgramAttachShape::CgroupSockopt {
                get: target.is_get(),
            },
            ProgramSpec::CgroupSockAddr { target } => ProgramAttachShape::CgroupSockAddr {
                family: target.attach_type.address_family(),
                hook: target.hook_kind(),
            },
            ProgramSpec::Netkit { target } => ProgramAttachShape::Netkit {
                endpoint: target.attach_type,
            },
            ProgramSpec::SkReuseport { target } => {
                ProgramAttachShape::SkReuseport { mode: target.mode }
            }
            ProgramSpec::LwtIn { .. } => ProgramAttachShape::Lwt {
                hook: ProgramAttachLwtHook::In,
            },
            ProgramSpec::LwtOut { .. } => ProgramAttachShape::Lwt {
                hook: ProgramAttachLwtHook::Out,
            },
            ProgramSpec::LwtXmit { .. } => ProgramAttachShape::Lwt {
                hook: ProgramAttachLwtHook::Xmit,
            },
            ProgramSpec::LwtSeg6Local { .. } => ProgramAttachShape::Lwt {
                hook: ProgramAttachLwtHook::Seg6Local,
            },
            ProgramSpec::Netfilter { target } => ProgramAttachShape::Netfilter {
                family: target.family,
                hook: target.hook,
                priority: target.priority,
                defrag: target.defrag,
            },
            ProgramSpec::LircMode2 { .. } => ProgramAttachShape::LircMode2,
            ProgramSpec::StructOps { value_type_name } => ProgramAttachShape::StructOps {
                family: StructOpsFamily::from_value_type_name(value_type_name),
            },
            ProgramSpec::StructOpsCallback {
                value_type_name,
                callback_name,
            } => ProgramAttachShape::StructOpsCallback {
                family: StructOpsFamily::from_value_type_name(value_type_name),
                sleepable: struct_ops_callback_is_sleepable(value_type_name, callback_name),
            },
            _ => ProgramAttachShape::Generic,
        }
    }
}

const ITERATOR_TARGET_COMPATIBILITY_REQUIREMENTS: &[(&str, ProgramCompatibilityRequirement)] = &[
    (
        "task",
        ProgramCompatibilityRequirement::BpfIteratorTaskTarget,
    ),
    (
        "task_file",
        ProgramCompatibilityRequirement::BpfIteratorTaskFileTarget,
    ),
    (
        "task_vma",
        ProgramCompatibilityRequirement::BpfIteratorTaskVmaTarget,
    ),
    (
        "bpf_map",
        ProgramCompatibilityRequirement::BpfIteratorBpfMapTarget,
    ),
    (
        "cgroup",
        ProgramCompatibilityRequirement::BpfIteratorCgroupTarget,
    ),
    (
        "bpf_map_elem",
        ProgramCompatibilityRequirement::BpfIteratorBpfMapElemTarget,
    ),
    (
        "bpf_sk_storage_map",
        ProgramCompatibilityRequirement::BpfIteratorBpfSkStorageMapTarget,
    ),
    (
        "sockmap",
        ProgramCompatibilityRequirement::BpfIteratorSockmapTarget,
    ),
    (
        "bpf_prog",
        ProgramCompatibilityRequirement::BpfIteratorBpfProgTarget,
    ),
    (
        "bpf_link",
        ProgramCompatibilityRequirement::BpfIteratorBpfLinkTarget,
    ),
    ("tcp", ProgramCompatibilityRequirement::BpfIteratorTcpTarget),
    ("udp", ProgramCompatibilityRequirement::BpfIteratorUdpTarget),
    (
        "unix",
        ProgramCompatibilityRequirement::BpfIteratorUnixTarget,
    ),
    (
        "ipv6_route",
        ProgramCompatibilityRequirement::BpfIteratorIpv6RouteTarget,
    ),
    (
        "ksym",
        ProgramCompatibilityRequirement::BpfIteratorKsymTarget,
    ),
    (
        "netlink",
        ProgramCompatibilityRequirement::BpfIteratorNetlinkTarget,
    ),
    (
        "kmem_cache",
        ProgramCompatibilityRequirement::BpfIteratorKmemCacheTarget,
    ),
    (
        "dmabuf",
        ProgramCompatibilityRequirement::BpfIteratorDmabufTarget,
    ),
];

fn iterator_target_compatibility_requirement(
    target: &str,
) -> Option<ProgramCompatibilityRequirement> {
    ITERATOR_TARGET_COMPATIBILITY_REQUIREMENTS
        .iter()
        .find_map(|(name, requirement)| (*name == target).then_some(*requirement))
}

fn push_compatibility_requirement(
    requirements: &mut Vec<ProgramCompatibilityRequirement>,
    requirement: ProgramCompatibilityRequirement,
) {
    if !requirements.contains(&requirement) {
        requirements.push(requirement);
    }
}

impl fmt::Display for ProgramSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let ProgramSpec::StructOpsCallback {
            value_type_name,
            callback_name,
        } = self
        {
            return write!(f, "struct_ops:{value_type_name}.{callback_name}");
        }

        let prefix = match self {
            ProgramSpec::Fentry {
                sleepable: true, ..
            } => "fentry.s",
            ProgramSpec::Fexit {
                sleepable: true, ..
            } => "fexit.s",
            ProgramSpec::FmodRet {
                sleepable: true, ..
            } => "fmod_ret.s",
            ProgramSpec::Lsm {
                sleepable: true, ..
            } => "lsm.s",
            ProgramSpec::Uprobe {
                sleepable: true, ..
            } => "uprobe.s",
            ProgramSpec::Uretprobe {
                sleepable: true, ..
            } => "uretprobe.s",
            ProgramSpec::UprobeMulti {
                sleepable: true, ..
            } => "uprobe.multi.s",
            ProgramSpec::UretprobeMulti {
                sleepable: true, ..
            } => "uretprobe.multi.s",
            _ => self.program_type().canonical_prefix(),
        };
        write!(f, "{}:{}", prefix, self.target_string())
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
        assert!(!connect4.supports_msg_source());
        assert!(connect4.is_connect());
        assert_eq!(connect4.hook_kind(), ProgramAttachSockAddrHook::Connect);
        assert!(connect4.hook_kind().is_connect());
        assert!(connect4.hook_kind().exposes_remote_tuple());
        assert!(!connect4.hook_kind().exposes_local_tuple());

        let sendmsg6 = CgroupSockAddrTarget::parse("/sys/fs/cgroup:sendmsg6")
            .expect("sendmsg6 target should parse");
        assert!(!sendmsg6.is_ipv4());
        assert!(sendmsg6.is_ipv6());
        assert!(sendmsg6.supports_msg_source());
        assert!(!sendmsg6.is_connect());
        assert_eq!(sendmsg6.hook_kind(), ProgramAttachSockAddrHook::SendMsg);
        assert!(sendmsg6.hook_kind().is_sendmsg());
        assert!(sendmsg6.hook_kind().exposes_remote_tuple());
        assert!(sendmsg6.hook_kind().exposes_local_ip_alias());
        assert!(!sendmsg6.hook_kind().exposes_local_tuple());

        let recvmsg4 = CgroupSockAddrTarget::parse("/sys/fs/cgroup:recvmsg4")
            .expect("recvmsg4 target should parse");
        assert!(recvmsg4.is_ipv4());
        assert!(!recvmsg4.is_ipv6());
        assert!(!recvmsg4.is_unix());
        assert!(!recvmsg4.supports_msg_source());
        assert!(!recvmsg4.is_connect());
        assert_eq!(recvmsg4.hook_kind(), ProgramAttachSockAddrHook::RecvMsg);
        assert!(!recvmsg4.hook_kind().is_sendmsg());
        assert!(recvmsg4.hook_kind().exposes_remote_tuple());
        assert!(!recvmsg4.hook_kind().exposes_local_ip_alias());

        let connect_unix = CgroupSockAddrTarget::parse("/sys/fs/cgroup:connect_unix")
            .expect("connect_unix target should parse");
        assert!(!connect_unix.is_ipv4());
        assert!(!connect_unix.is_ipv6());
        assert!(connect_unix.is_unix());
        assert!(connect_unix.aya_attach_type().is_none());
        assert!(connect_unix.is_connect());
        assert_eq!(connect_unix.hook_kind(), ProgramAttachSockAddrHook::Connect);
        assert_eq!(connect_unix.section_name(), "cgroup/connect_unix");
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

    #[test]
    fn test_program_spec_attach_shape_tracks_typed_targets() {
        let xdp = ProgramSpec::parse("xdp:lo:drv:frags").expect("xdp spec should parse");
        let perf_event =
            ProgramSpec::parse("perf_event:hardware:instructions:cpu=2:pid=42:freq=99")
                .expect("perf_event spec should parse");
        let socket_filter = ProgramSpec::parse("socket_filter:tcp6:[::1]:8080")
            .expect("socket_filter spec should parse");
        let syscall = ProgramSpec::parse("syscall:demo").expect("syscall spec should parse");
        let iter = ProgramSpec::parse("iter:task").expect("iter spec should parse");
        let sk_lookup =
            ProgramSpec::parse("sk_lookup:/proc/self/ns/net").expect("sk_lookup spec should parse");
        let flow_dissector = ProgramSpec::parse("flow_dissector:/proc/self/ns/net")
            .expect("flow_dissector spec should parse");
        let sk_msg =
            ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo").expect("sk_msg spec should parse");
        let sk_skb =
            ProgramSpec::parse("sk_skb:/sys/fs/bpf/demo").expect("sk_skb spec should parse");
        let sk_skb_parser = ProgramSpec::parse("sk_skb_parser:/sys/fs/bpf/demo")
            .expect("sk_skb_parser spec should parse");
        let tc = ProgramSpec::from_program_type_target(EbpfProgramType::Tc, "lo:ingress")
            .expect("tc target should parse");
        let tcx = ProgramSpec::from_program_type_target(EbpfProgramType::Tcx, "lo:egress")
            .expect("tcx target should parse");
        let tc_action =
            ProgramSpec::parse("tc_action:demo-action").expect("tc_action spec should parse");
        let netkit = ProgramSpec::from_program_type_target(EbpfProgramType::Netkit, "nk0:primary")
            .expect("netkit target should parse");
        let sk_reuseport_migrate =
            ProgramSpec::parse("sk_reuseport:migrate").expect("sk_reuseport spec should parse");
        let lwt_out = ProgramSpec::parse("lwt_out:demo-route").expect("lwt_out spec should parse");
        let netfilter = ProgramSpec::parse("netfilter:ipv6:local_out:priority=-100:defrag")
            .expect("netfilter spec should parse");
        let cgroup_skb = ProgramSpec::from_program_type_target(
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:egress",
        )
        .expect("cgroup_skb egress target should parse");
        let cgroup_device = ProgramSpec::parse("cgroup_device:/sys/fs/cgroup")
            .expect("cgroup_device spec should parse");
        let cgroup_sysctl = ProgramSpec::parse("cgroup_sysctl:/sys/fs/cgroup")
            .expect("cgroup_sysctl spec should parse");
        let sock_ops =
            ProgramSpec::parse("sock_ops:/sys/fs/cgroup").expect("sock_ops spec should parse");
        let sock_post_bind = ProgramSpec::from_program_type_target(
            EbpfProgramType::CgroupSock,
            "/sys/fs/cgroup:post_bind6",
        )
        .expect("cgroup_sock post_bind target should parse");
        let sockopt_get = ProgramSpec::from_program_type_target(
            EbpfProgramType::CgroupSockopt,
            "/sys/fs/cgroup:get",
        )
        .expect("cgroup_sockopt get target should parse");
        let sendmsg6 = ProgramSpec::from_program_type_target(
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:sendmsg6",
        )
        .expect("cgroup_sock_addr sendmsg6 target should parse");
        let connect_unix = ProgramSpec::from_program_type_target(
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:connect_unix",
        )
        .expect("cgroup_sock_addr connect_unix target should parse");
        let lirc_mode2 =
            ProgramSpec::parse("lirc_mode2:/dev/lirc0").expect("lirc_mode2 spec should parse");
        let sched_ext_struct_ops = ProgramSpec::StructOps {
            value_type_name: "sched_ext_ops".to_string(),
        };
        let sched_ext_select_cpu = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "select_cpu".to_string(),
        };
        let sched_ext_init = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "init".to_string(),
        };

        assert_eq!(
            xdp.attach_shape(),
            ProgramAttachShape::Xdp {
                mode: XdpAttachMode::Driver,
                frags: true,
            }
        );
        assert_eq!(
            perf_event.attach_shape(),
            ProgramAttachShape::PerfEvent {
                event: PerfEventEvent::Hardware(PerfEventHardwareEvent::Instructions),
                cpu: Some(2),
                pid: Some(42),
                sample_policy: PerfEventSamplePolicy::Frequency(99),
            }
        );
        assert_eq!(
            socket_filter.attach_shape(),
            ProgramAttachShape::SocketFilter {
                socket_kind: SocketFilterSocketKind::Tcp6,
            }
        );
        assert_eq!(syscall.attach_shape(), ProgramAttachShape::Syscall);
        assert_eq!(iter.attach_shape(), ProgramAttachShape::Iter);
        assert_eq!(sk_lookup.attach_shape(), ProgramAttachShape::SkLookup);
        assert_eq!(
            flow_dissector.attach_shape(),
            ProgramAttachShape::FlowDissector
        );
        assert_eq!(sk_msg.attach_shape(), ProgramAttachShape::SkMsg);
        assert_eq!(
            sk_skb.attach_shape(),
            ProgramAttachShape::SkSkb { parser: false }
        );
        assert_eq!(
            sk_skb_parser.attach_shape(),
            ProgramAttachShape::SkSkb { parser: true }
        );
        assert_eq!(tc.attach_shape(), ProgramAttachShape::Tc { ingress: true });
        assert!(tc.attach_shape().is_tc_ingress());
        assert!(!tc.attach_shape().is_tc_egress());
        assert_eq!(
            tcx.attach_shape(),
            ProgramAttachShape::Tc { ingress: false }
        );
        assert!(tcx.attach_shape().is_tc_egress());
        assert_eq!(tcx.section_name(), "tcx/egress");
        assert_eq!(tc_action.attach_shape(), ProgramAttachShape::TcAction);
        assert_eq!(
            netkit.attach_shape(),
            ProgramAttachShape::Netkit {
                endpoint: NetkitAttachType::Primary,
            }
        );
        assert_eq!(
            sk_reuseport_migrate.attach_shape(),
            ProgramAttachShape::SkReuseport {
                mode: SkReuseportMode::Migrate,
            }
        );
        assert_eq!(
            lwt_out.attach_shape(),
            ProgramAttachShape::Lwt {
                hook: ProgramAttachLwtHook::Out,
            }
        );
        assert_eq!(
            netfilter.attach_shape(),
            ProgramAttachShape::Netfilter {
                family: NetfilterProtocolFamily::Ipv6,
                hook: NetfilterHook::LocalOut,
                priority: -100,
                defrag: true,
            }
        );
        assert_eq!(netkit.section_name(), "netkit/primary");
        assert_eq!(
            cgroup_skb.attach_shape(),
            ProgramAttachShape::CgroupSkb { ingress: false }
        );
        assert!(!cgroup_skb.attach_shape().is_cgroup_skb_ingress());
        assert_eq!(
            cgroup_device.attach_shape(),
            ProgramAttachShape::CgroupDevice
        );
        assert_eq!(
            cgroup_sysctl.attach_shape(),
            ProgramAttachShape::CgroupSysctl
        );
        assert_eq!(sock_ops.attach_shape(), ProgramAttachShape::SockOps);
        assert_eq!(
            sock_post_bind.attach_shape(),
            ProgramAttachShape::CgroupSock {
                post_bind: true,
                family: Some(ProgramAttachAddressFamily::Ipv6),
            }
        );
        assert!(sock_post_bind.attach_shape().is_cgroup_sock_post_bind());
        assert!(
            sock_post_bind
                .attach_shape()
                .is_cgroup_sock_post_bind_family(ProgramAttachAddressFamily::Ipv6)
        );
        assert!(
            !sock_post_bind
                .attach_shape()
                .is_cgroup_sock_post_bind_family(ProgramAttachAddressFamily::Ipv4)
        );
        assert_eq!(
            sockopt_get.attach_shape(),
            ProgramAttachShape::CgroupSockopt { get: true }
        );
        assert!(sockopt_get.attach_shape().is_cgroup_sockopt_get());
        assert!(!sockopt_get.attach_shape().is_cgroup_sockopt_set());
        assert!(sockopt_get.attach_shape().is_cgroup_sockopt());
        assert_eq!(
            sendmsg6.attach_shape(),
            ProgramAttachShape::CgroupSockAddr {
                family: ProgramAttachAddressFamily::Ipv6,
                hook: ProgramAttachSockAddrHook::SendMsg,
            }
        );
        assert_eq!(
            sendmsg6.attach_shape().cgroup_sock_addr(),
            Some((
                ProgramAttachAddressFamily::Ipv6,
                ProgramAttachSockAddrHook::SendMsg
            ))
        );
        assert_eq!(
            connect_unix.attach_shape(),
            ProgramAttachShape::CgroupSockAddr {
                family: ProgramAttachAddressFamily::Unix,
                hook: ProgramAttachSockAddrHook::Connect,
            }
        );
        assert_eq!(connect_unix.section_name(), "cgroup/connect_unix");
        assert_eq!(lirc_mode2.attach_shape(), ProgramAttachShape::LircMode2);
        assert_eq!(
            sched_ext_struct_ops.attach_shape(),
            ProgramAttachShape::StructOps {
                family: StructOpsFamily::SchedExt,
            }
        );
        assert_eq!(
            sched_ext_select_cpu.attach_shape(),
            ProgramAttachShape::StructOpsCallback {
                family: StructOpsFamily::SchedExt,
                sleepable: false,
            }
        );
        assert_eq!(
            sched_ext_select_cpu.attach_shape().struct_ops_callback(),
            Some((StructOpsFamily::SchedExt, false))
        );
        assert_eq!(
            sched_ext_init.attach_shape(),
            ProgramAttachShape::StructOpsCallback {
                family: StructOpsFamily::SchedExt,
                sleepable: true,
            }
        );
        assert_eq!(
            sched_ext_init.attach_shape().struct_ops_callback(),
            Some((StructOpsFamily::SchedExt, true))
        );
        assert_eq!(sched_ext_select_cpu.section_name(), "struct_ops/select_cpu");
        assert_eq!(sched_ext_init.section_name(), "struct_ops.s/init");
    }

    #[test]
    fn test_program_spec_compatibility_requirements_add_target_features() {
        let plain_xdp = ProgramSpec::parse("xdp:lo").expect("plain xdp spec should parse");
        assert!(
            plain_xdp.requires_compatibility_feature(ProgramCompatibilityRequirement::XdpProgram)
        );
        assert!(
            plain_xdp
                .requires_compatibility_feature(ProgramCompatibilityRequirement::XdpSkbAttachMode)
        );
        assert!(
            !plain_xdp
                .requires_compatibility_feature(ProgramCompatibilityRequirement::XdpMultiBuffer)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &plain_xdp.compatibility_requirements()
            ),
            Some("4.12")
        );

        let xdp_frags = ProgramSpec::parse("xdp:lo:frags").expect("xdp frags spec should parse");
        assert!(
            xdp_frags
                .requires_compatibility_feature(ProgramCompatibilityRequirement::XdpMultiBuffer)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &xdp_frags.compatibility_requirements()
            ),
            Some("5.18")
        );

        let xdp_drv = ProgramSpec::parse("xdp:lo:drv").expect("xdp drv spec should parse");
        assert!(
            xdp_drv
                .requires_compatibility_feature(ProgramCompatibilityRequirement::XdpDrvAttachMode)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &xdp_drv.compatibility_requirements()
            ),
            Some("4.12")
        );

        let xdp_hw = ProgramSpec::parse("xdp:lo:hw").expect("xdp hw spec should parse");
        assert!(
            xdp_hw.requires_compatibility_feature(ProgramCompatibilityRequirement::XdpHwAttachMode)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &xdp_hw.compatibility_requirements()
            ),
            Some("4.13")
        );

        let fentry_sleepable =
            ProgramSpec::parse("fentry.s:do_sys_openat2").expect("sleepable fentry should parse");
        assert!(
            fentry_sleepable
                .requires_compatibility_feature(ProgramCompatibilityRequirement::KernelBtf)
        );
        assert!(
            fentry_sleepable
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SleepableProgram)
        );

        let struct_ops =
            ProgramSpec::parse("struct_ops:demo_ops").expect("generic struct_ops should parse");
        assert!(
            struct_ops.requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
        );
        assert!(
            !struct_ops
                .requires_compatibility_feature(ProgramCompatibilityRequirement::TcpCongestionOps)
        );
        assert!(
            !struct_ops.requires_compatibility_feature(ProgramCompatibilityRequirement::SchedExt)
        );
        assert!(
            !struct_ops.requires_compatibility_feature(ProgramCompatibilityRequirement::QdiscOps)
        );

        let tcp_congestion = ProgramSpec::parse("struct_ops:tcp_congestion_ops")
            .expect("tcp_congestion_ops spec should parse");
        assert!(
            tcp_congestion
                .requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
        );
        assert!(
            tcp_congestion
                .requires_compatibility_feature(ProgramCompatibilityRequirement::TcpCongestionOps)
        );
        assert!(
            !tcp_congestion
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SchedExt)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &tcp_congestion.compatibility_requirements()
            ),
            Some("5.6")
        );
        let tcp_congestion_init = ProgramSpec::StructOpsCallback {
            value_type_name: "tcp_congestion_ops".to_string(),
            callback_name: "init".to_string(),
        };
        assert!(
            tcp_congestion_init
                .requires_compatibility_feature(ProgramCompatibilityRequirement::TcpCongestionOps)
        );

        for (spec_text, requirement, minimum) in [
            (
                "struct_ops:hid_bpf_ops",
                ProgramCompatibilityRequirement::HidBpfOps,
                "6.11",
            ),
            (
                "struct_ops:Qdisc_ops",
                ProgramCompatibilityRequirement::QdiscOps,
                "6.16",
            ),
        ] {
            let spec = ProgramSpec::parse(spec_text).expect("struct_ops family spec should parse");
            assert!(
                spec.requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
            );
            assert!(spec.requires_compatibility_feature(requirement));
            assert_eq!(
                ProgramCompatibilityRequirement::effective_minimum_kernel(
                    &spec.compatibility_requirements()
                ),
                Some(minimum)
            );
        }

        let sched_ext =
            ProgramSpec::parse("struct_ops:sched_ext_ops").expect("sched_ext should parse");
        assert!(
            sched_ext.requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
        );
        assert!(
            sched_ext.requires_compatibility_feature(ProgramCompatibilityRequirement::SchedExt)
        );

        let sched_ext_select_cpu = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "select_cpu".to_string(),
        };
        assert!(
            sched_ext_select_cpu
                .requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
        );
        assert!(
            sched_ext_select_cpu
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SchedExt)
        );
        assert!(
            !sched_ext_select_cpu
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SleepableProgram)
        );

        let sched_ext_init = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "init".to_string(),
        };
        assert!(
            sched_ext_init
                .requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
        );
        assert!(
            sched_ext_init
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SchedExt)
        );
        assert!(
            sched_ext_init
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SleepableProgram)
        );

        let cgroup_unix = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
            .expect("cgroup unix socket-address spec should parse");
        assert!(
            cgroup_unix.requires_compatibility_feature(ProgramCompatibilityRequirement::CgroupV2)
        );
        assert!(cgroup_unix.requires_compatibility_feature(
            ProgramCompatibilityRequirement::CgroupSockAddrProgram
        ));
        assert!(
            cgroup_unix.requires_compatibility_feature(
                ProgramCompatibilityRequirement::CgroupUnixSockAddr
            )
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &cgroup_unix.compatibility_requirements()
            ),
            Some("6.7")
        );

        let uprobe_multi =
            ProgramSpec::parse("uprobe.multi:/bin/bash:read*").expect("uprobe.multi should parse");
        assert!(
            uprobe_multi
                .requires_compatibility_feature(ProgramCompatibilityRequirement::UprobeMulti)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &uprobe_multi.compatibility_requirements()
            ),
            Some("6.6")
        );

        let sk_reuseport_select =
            ProgramSpec::parse("sk_reuseport:select").expect("sk_reuseport select should parse");
        assert!(
            sk_reuseport_select
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SkReuseportAttach)
        );
        assert!(
            !sk_reuseport_select.requires_compatibility_feature(
                ProgramCompatibilityRequirement::SkReuseportMigration
            )
        );

        let sk_reuseport_migrate =
            ProgramSpec::parse("sk_reuseport:migrate").expect("sk_reuseport migrate should parse");
        assert!(
            sk_reuseport_migrate
                .requires_compatibility_feature(ProgramCompatibilityRequirement::SkReuseportAttach)
        );
        assert!(
            sk_reuseport_migrate.requires_compatibility_feature(
                ProgramCompatibilityRequirement::SkReuseportMigration
            )
        );

        let lwt_in = ProgramSpec::parse("lwt_in:demo-route").expect("lwt_in should parse");
        assert!(lwt_in.requires_compatibility_feature(ProgramCompatibilityRequirement::RouteLwt));
        assert!(
            !lwt_in
                .requires_compatibility_feature(ProgramCompatibilityRequirement::RouteLwtSeg6Local)
        );

        let lwt_seg6local =
            ProgramSpec::parse("lwt_seg6local:demo-route").expect("lwt_seg6local should parse");
        assert!(
            lwt_seg6local.requires_compatibility_feature(ProgramCompatibilityRequirement::RouteLwt)
        );
        assert!(
            lwt_seg6local
                .requires_compatibility_feature(ProgramCompatibilityRequirement::RouteLwtSeg6Local)
        );

        let netfilter =
            ProgramSpec::parse("netfilter:ipv4:pre_routing").expect("netfilter spec should parse");
        assert!(
            netfilter
                .requires_compatibility_feature(ProgramCompatibilityRequirement::NetfilterLink)
        );
        assert!(
            !netfilter
                .requires_compatibility_feature(ProgramCompatibilityRequirement::NetfilterDefrag)
        );

        let netfilter_defrag = ProgramSpec::parse("netfilter:ipv4:pre_routing:defrag")
            .expect("netfilter defrag spec should parse");
        assert!(
            netfilter_defrag
                .requires_compatibility_feature(ProgramCompatibilityRequirement::NetfilterDefrag)
        );
        assert_eq!(
            ProgramCompatibilityRequirement::effective_minimum_kernel(
                &netfilter_defrag.compatibility_requirements()
            ),
            Some("6.6")
        );

        let sk_msg =
            ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap").expect("sk_msg should parse");
        assert!(
            sk_msg.requires_compatibility_feature(ProgramCompatibilityRequirement::SockMapAttach)
        );
        assert!(
            sk_msg.requires_compatibility_feature(
                ProgramCompatibilityRequirement::SkMsgSockMapAttach
            )
        );

        let sk_skb =
            ProgramSpec::parse("sk_skb:/sys/fs/bpf/demo_sockmap").expect("sk_skb should parse");
        assert!(
            sk_skb.requires_compatibility_feature(ProgramCompatibilityRequirement::SockMapAttach)
        );
        assert!(
            sk_skb.requires_compatibility_feature(
                ProgramCompatibilityRequirement::SkSkbSockMapAttach
            )
        );

        for (target, requirement) in ITERATOR_TARGET_COMPATIBILITY_REQUIREMENTS {
            let spec_text = format!("iter:{target}");
            let spec = ProgramSpec::parse(&spec_text).expect("iter spec should parse");
            let minimum_kernel = requirement
                .minimum_kernel()
                .expect("iterator target requirement should be versioned");
            assert!(
                spec.requires_compatibility_feature(ProgramCompatibilityRequirement::BpfIterator)
            );
            assert!(spec.requires_compatibility_feature(*requirement));
            assert_eq!(
                ProgramCompatibilityRequirement::effective_minimum_kernel(
                    &spec.compatibility_requirements()
                ),
                Some(minimum_kernel)
            );
            assert_eq!(requirement.category(), "iterator-target");
            assert!(
                requirement.minimum_kernel_source().is_some(),
                "{requirement:?} should have a primary source"
            );
        }

        for requirement in ProgramCompatibilityRequirement::all()
            .iter()
            .copied()
            .filter(|requirement| requirement.category() == "iterator-target")
        {
            assert!(
                ITERATOR_TARGET_COMPATIBILITY_REQUIREMENTS
                    .iter()
                    .any(|(_, mapped)| *mapped == requirement),
                "{requirement:?} should be mapped from an iter:TARGET spec"
            );
        }
    }

    #[test]
    fn test_program_spec_live_attach_policy_accounts_for_loader_and_safety() {
        let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        assert_eq!(
            xdp.live_attach_policy(),
            ProgramLiveAttachPolicy {
                loader_supported: true,
                default_allowed: true,
                requires_opt_in: false,
                note: None,
            }
        );

        let raw_tracepoint_writable =
            ProgramSpec::parse("raw_tracepoint.w:sys_enter").expect("raw_tp.w spec should parse");
        let raw_policy = raw_tracepoint_writable.live_attach_policy();
        assert!(!raw_policy.loader_supported);
        assert!(!raw_policy.default_allowed);
        assert!(!raw_policy.requires_opt_in);
        assert!(
            raw_policy
                .note
                .is_some_and(|note| note.contains("writable raw-tracepoint"))
        );

        let cgroup_sock_addr_unix =
            ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
                .expect("cgroup_sock_addr unix spec should parse");
        let cgroup_unix_policy = cgroup_sock_addr_unix.live_attach_policy();
        assert!(!cgroup_unix_policy.loader_supported);
        assert!(!cgroup_unix_policy.default_allowed);
        assert!(!cgroup_unix_policy.requires_opt_in);
        assert!(
            cgroup_unix_policy
                .note
                .is_some_and(|note| note.contains("BPF_CGROUP_UNIX"))
        );

        let sched_ext =
            ProgramSpec::parse("struct_ops:sched_ext_ops").expect("sched_ext spec should parse");
        let sched_ext_policy = sched_ext.live_attach_policy();
        assert!(sched_ext_policy.loader_supported);
        assert!(!sched_ext_policy.default_allowed);
        assert!(sched_ext_policy.requires_opt_in);
        assert!(
            sched_ext_policy
                .note
                .is_some_and(|note| note.contains("sched_ext"))
        );
    }

    #[test]
    fn test_program_spec_modeled_metadata_accessors() {
        let tracepoint = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
            .expect("tracepoint spec should parse");
        let raw_tracepoint_writable = ProgramSpec::parse("raw_tracepoint.w:sys_enter")
            .expect("writable raw tracepoint spec should parse");
        let ksyscall =
            ProgramSpec::parse("ksyscall:nanosleep").expect("ksyscall spec should parse");
        let kretsyscall =
            ProgramSpec::parse("kretsyscall:nanosleep").expect("kretsyscall spec should parse");
        let kprobe_multi =
            ProgramSpec::parse("kprobe.multi:vfs_*").expect("kprobe.multi spec should parse");
        let kretprobe_multi =
            ProgramSpec::parse("kretprobe.multi:vfs_*").expect("kretprobe.multi spec should parse");
        let fmod_ret = ProgramSpec::parse("fmod_ret:bpf_modify_return_test")
            .expect("fmod_ret spec should parse");
        let sleepable_fmod_ret = ProgramSpec::parse("fmod_ret.s:bpf_modify_return_test")
            .expect("sleepable fmod_ret spec should parse");
        let lsm_cgroup =
            ProgramSpec::parse("lsm_cgroup:socket_bind").expect("lsm_cgroup spec should parse");
        let struct_ops =
            ProgramSpec::parse("struct_ops:sched_ext_ops").expect("struct_ops spec should parse");
        let uprobe =
            ProgramSpec::parse("uprobe:/bin/bash:main+0x4@123").expect("uprobe spec should parse");
        let sleepable_uprobe = ProgramSpec::parse("uprobe.s:/bin/bash:main")
            .expect("sleepable uprobe spec should parse");
        let sleepable_uretprobe = ProgramSpec::parse("uretprobe.s:/lib/libc.so.6:malloc")
            .expect("sleepable uretprobe spec should parse");
        let uprobe_multi = ProgramSpec::parse("uprobe.multi:/bin/bash:read*")
            .expect("uprobe.multi spec should parse");
        let sleepable_uprobe_multi = ProgramSpec::parse("uprobe.multi.s:/bin/bash:read*")
            .expect("sleepable uprobe.multi spec should parse");
        let uretprobe_multi = ProgramSpec::parse("uretprobe.multi:/bin/bash:read*")
            .expect("uretprobe.multi spec should parse");
        let sleepable_uretprobe_multi = ProgramSpec::parse("uretprobe.multi.s:/bin/bash:read*")
            .expect("sleepable uretprobe.multi spec should parse");
        let xdp = ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        let perf_event = ProgramSpec::parse("perf_event:software:cpu-clock:cpu=1")
            .expect("perf_event spec should parse");
        let socket_filter = ProgramSpec::parse("socket_filter:tcp4:127.0.0.1:8080")
            .expect("socket_filter spec should parse");
        let sk_lookup =
            ProgramSpec::parse("sk_lookup:/proc/self/ns/net").expect("sk_lookup spec should parse");
        let flow_dissector = ProgramSpec::parse("flow_dissector:/proc/self/ns/net")
            .expect("flow_dissector spec should parse");
        let netfilter = ProgramSpec::parse("netfilter:ipv4:pre_routing:priority=-100:defrag")
            .expect("netfilter spec should parse");
        let lwt_xmit =
            ProgramSpec::parse("lwt_xmit:demo-route").expect("lwt_xmit spec should parse");
        let extension =
            ProgramSpec::parse("freplace:replace_me").expect("freplace spec should parse");
        let syscall = ProgramSpec::parse("syscall:demo").expect("syscall spec should parse");
        let iter = ProgramSpec::parse("iter:task").expect("iter spec should parse");
        let lirc =
            ProgramSpec::parse("lirc_mode2:/dev/lirc0").expect("lirc_mode2 spec should parse");
        let tc = ProgramSpec::parse("tc:lo:ingress").expect("tc spec should parse");
        let tcx = ProgramSpec::parse("tcx:lo:egress").expect("tcx spec should parse");
        let netkit = ProgramSpec::parse("netkit:nk0:peer").expect("netkit spec should parse");
        let tc_action =
            ProgramSpec::parse("tc_action:demo-action").expect("tc_action spec should parse");
        let cgroup_skb = ProgramSpec::parse("cgroup_skb:/sys/fs/cgroup:egress")
            .expect("cgroup_skb spec should parse");
        let cgroup_sock = ProgramSpec::parse("cgroup_sock:/sys/fs/cgroup:sock_create")
            .expect("cgroup_sock spec should parse");
        let sk_msg = ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap")
            .expect("sk_msg spec should parse");
        let callback = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "select_cpu".to_string(),
        };

        assert_eq!(
            tracepoint.tracepoint_parts(),
            Some(("syscalls", "sys_enter_openat"))
        );
        assert_eq!(raw_tracepoint_writable.target_string(), "sys_enter");
        assert_eq!(
            raw_tracepoint_writable.section_name(),
            "raw_tracepoint.w/sys_enter"
        );
        assert_eq!(ksyscall.program_type(), EbpfProgramType::Ksyscall);
        assert_eq!(ksyscall.target_string(), "nanosleep");
        assert_eq!(ksyscall.section_name(), "ksyscall/nanosleep");
        assert_eq!(kretsyscall.program_type(), EbpfProgramType::KretSyscall);
        assert_eq!(kretsyscall.target_string(), "nanosleep");
        assert_eq!(kretsyscall.section_name(), "kretsyscall/nanosleep");
        assert_eq!(kprobe_multi.program_type(), EbpfProgramType::KprobeMulti);
        assert_eq!(kprobe_multi.target_string(), "vfs_*");
        assert_eq!(kprobe_multi.section_name(), "kprobe.multi/vfs_*");
        assert_eq!(kprobe_multi.to_string(), "kprobe.multi:vfs_*");
        assert_eq!(
            kretprobe_multi.program_type(),
            EbpfProgramType::KretprobeMulti
        );
        assert_eq!(kretprobe_multi.target_string(), "vfs_*");
        assert_eq!(kretprobe_multi.section_name(), "kretprobe.multi/vfs_*");
        assert_eq!(kretprobe_multi.to_string(), "kretprobe.multi:vfs_*");
        assert_eq!(fmod_ret.program_type(), EbpfProgramType::FmodRet);
        assert_eq!(fmod_ret.target_string(), "bpf_modify_return_test");
        assert_eq!(fmod_ret.section_name(), "fmod_ret/bpf_modify_return_test");
        assert_eq!(
            sleepable_fmod_ret.section_name(),
            "fmod_ret.s/bpf_modify_return_test"
        );
        assert_eq!(
            sleepable_fmod_ret.to_string(),
            "fmod_ret.s:bpf_modify_return_test"
        );
        assert_eq!(lsm_cgroup.program_type(), EbpfProgramType::LsmCgroup);
        assert_eq!(lsm_cgroup.target_string(), "socket_bind");
        assert_eq!(lsm_cgroup.section_name(), "lsm_cgroup/socket_bind");
        assert_eq!(lsm_cgroup.to_string(), "lsm_cgroup:socket_bind");
        assert_eq!(tracepoint.struct_ops_value_type_name(), None);
        assert_eq!(struct_ops.tracepoint_parts(), None);
        assert_eq!(
            uprobe
                .uprobe_target()
                .map(|target| target.binary_path.as_str()),
            Some("/bin/bash")
        );
        assert_eq!(sleepable_uprobe.program_type(), EbpfProgramType::Uprobe);
        assert_eq!(sleepable_uprobe.section_name(), "uprobe.s//bin/bash:main");
        assert_eq!(sleepable_uprobe.to_string(), "uprobe.s:/bin/bash:main");
        assert_eq!(
            sleepable_uretprobe.program_type(),
            EbpfProgramType::Uretprobe
        );
        assert_eq!(
            sleepable_uretprobe.section_name(),
            "uretprobe.s//lib/libc.so.6:malloc"
        );
        assert_eq!(
            sleepable_uretprobe.to_string(),
            "uretprobe.s:/lib/libc.so.6:malloc"
        );
        assert_eq!(uprobe_multi.program_type(), EbpfProgramType::UprobeMulti);
        assert_eq!(
            uprobe_multi
                .uprobe_multi_target()
                .map(|target| target.function_pattern.as_str()),
            Some("read*")
        );
        assert_eq!(uprobe_multi.section_name(), "uprobe.multi//bin/bash:read*");
        assert_eq!(uprobe_multi.to_string(), "uprobe.multi:/bin/bash:read*");
        assert_eq!(
            sleepable_uprobe_multi.section_name(),
            "uprobe.multi.s//bin/bash:read*"
        );
        assert_eq!(
            sleepable_uprobe_multi.to_string(),
            "uprobe.multi.s:/bin/bash:read*"
        );
        assert_eq!(
            uretprobe_multi.program_type(),
            EbpfProgramType::UretprobeMulti
        );
        assert_eq!(
            uretprobe_multi
                .uprobe_multi_target()
                .map(|target| target.binary_path.as_str()),
            Some("/bin/bash")
        );
        assert_eq!(
            uretprobe_multi.section_name(),
            "uretprobe.multi//bin/bash:read*"
        );
        assert_eq!(
            sleepable_uretprobe_multi.section_name(),
            "uretprobe.multi.s//bin/bash:read*"
        );
        assert_eq!(
            sleepable_uretprobe_multi.to_string(),
            "uretprobe.multi.s:/bin/bash:read*"
        );
        assert_eq!(
            xdp.xdp_target().map(|target| target.interface.as_str()),
            Some("lo")
        );
        assert_eq!(
            xdp.xdp_target().map(|target| target.attach_mode),
            Some(XdpAttachMode::Skb)
        );
        assert_eq!(xdp.xdp_target().map(|target| target.frags), Some(false));
        assert_eq!(
            perf_event.perf_event_target().map(|target| target.cpu),
            Some(Some(1))
        );
        assert_eq!(
            socket_filter
                .socket_filter_target()
                .map(|target| target.bind_port),
            Some(8080)
        );
        assert_eq!(
            sk_lookup
                .sk_lookup_target()
                .map(|target| target.netns_path.as_str()),
            Some("/proc/self/ns/net")
        );
        assert_eq!(
            flow_dissector
                .flow_dissector_target()
                .map(|target| target.netns_path.as_str()),
            Some("/proc/self/ns/net")
        );
        assert_eq!(flow_dissector.section_name(), "flow_dissector");
        assert_eq!(
            netfilter.netfilter_target().map(|target| target.family),
            Some(NetfilterProtocolFamily::Ipv4)
        );
        assert_eq!(
            netfilter.netfilter_target().map(|target| target.hook),
            Some(NetfilterHook::PreRouting)
        );
        assert_eq!(
            netfilter.netfilter_target().map(|target| target.priority),
            Some(-100)
        );
        assert_eq!(
            netfilter.netfilter_target().map(|target| target.defrag),
            Some(true)
        );
        assert_eq!(netfilter.section_name(), "netfilter");
        assert_eq!(
            lwt_xmit.lwt_target().map(|target| target.route.as_str()),
            Some("demo-route")
        );
        assert_eq!(lwt_xmit.section_name(), "lwt_xmit");
        assert_eq!(extension.program_type(), EbpfProgramType::Extension);
        assert_eq!(extension.target_string(), "replace_me");
        assert_eq!(extension.section_name(), "freplace/replace_me");
        assert_eq!(syscall.program_type(), EbpfProgramType::Syscall);
        assert_eq!(syscall.target_string(), "demo");
        assert_eq!(syscall.section_name(), "syscall");
        assert_eq!(iter.program_type(), EbpfProgramType::Iter);
        assert_eq!(iter.target_string(), "task");
        assert_eq!(iter.section_name(), "iter/task");
        assert_eq!(
            lirc.lirc_mode2_target()
                .map(|target| target.device_path.as_str()),
            Some("/dev/lirc0")
        );
        assert_eq!(
            tc.tc_target().map(|target| target.interface.as_str()),
            Some("lo")
        );
        assert_eq!(tcx.program_type(), EbpfProgramType::Tcx);
        assert_eq!(tcx.target_string(), "lo:egress");
        assert_eq!(tcx.section_name(), "tcx/egress");
        assert_eq!(tcx.to_string(), "tcx:lo:egress");
        assert_eq!(
            netkit
                .netkit_target()
                .map(|target| target.interface.as_str()),
            Some("nk0")
        );
        assert_eq!(netkit.program_type(), EbpfProgramType::Netkit);
        assert_eq!(netkit.target_string(), "nk0:peer");
        assert_eq!(netkit.section_name(), "netkit/peer");
        assert_eq!(netkit.to_string(), "netkit:nk0:peer");
        assert_eq!(tc_action.target_string(), "demo-action");
        assert_eq!(tc_action.section_name(), "action");
        assert_eq!(
            cgroup_skb
                .cgroup_skb_target()
                .map(|target| target.cgroup_path.as_str()),
            Some("/sys/fs/cgroup")
        );
        assert_eq!(
            struct_ops.struct_ops_value_type_name(),
            Some("sched_ext_ops")
        );
        assert_eq!(
            struct_ops.struct_ops_family(),
            Some(StructOpsFamily::SchedExt)
        );
        assert_eq!(callback.tracepoint_parts(), None);
        assert_eq!(callback.struct_ops_value_type_name(), Some("sched_ext_ops"));
        assert_eq!(
            callback.struct_ops_family(),
            Some(StructOpsFamily::SchedExt)
        );
        assert_eq!(tracepoint.cgroup_path(), None);
        assert_eq!(cgroup_sock.cgroup_path(), Some("/sys/fs/cgroup"));
        assert_eq!(tracepoint.pinned_map_path(), None);
        assert_eq!(sk_msg.pinned_map_path(), Some("/sys/fs/bpf/demo_sockmap"));
        assert_eq!(callback.target_string(), "select_cpu");
        assert!(struct_ops_callback_is_sleepable("sched_ext_ops", "init"));
        assert!(!struct_ops_callback_is_sleepable(
            "sched_ext_ops",
            "dispatch"
        ));
        assert_eq!(tracepoint.struct_ops_family(), None);
        assert_eq!(
            ProgramSpec::parse("struct_ops:tcp_congestion_ops")
                .expect("tcp_congestion_ops spec should parse")
                .struct_ops_family(),
            Some(StructOpsFamily::TcpCongestion)
        );
        assert_eq!(
            ProgramSpec::parse("struct_ops:hid_bpf_ops")
                .expect("hid_bpf_ops spec should parse")
                .struct_ops_family(),
            Some(StructOpsFamily::HidBpf)
        );
        assert_eq!(
            ProgramSpec::parse("struct_ops:Qdisc_ops")
                .expect("Qdisc_ops spec should parse")
                .struct_ops_family(),
            Some(StructOpsFamily::Qdisc)
        );
    }

    #[test]
    fn test_supported_program_types_parse_canonical_representative_specs() {
        for &program_type in EbpfProgramType::supported_program_types() {
            let target = ProgramSpec::representative_target_for_program_type(program_type);
            let direct = ProgramSpec::from_program_type_target(program_type, target)
                .unwrap_or_else(|err| {
                    panic!(
                        "{} representative target should parse directly: {err}",
                        program_type.canonical_prefix()
                    )
                });
            let parsed =
                ProgramSpec::parse(&format!("{}:{target}", program_type.canonical_prefix()))
                    .unwrap_or_else(|err| {
                        panic!(
                            "{} canonical representative spec should parse: {err}",
                            program_type.canonical_prefix()
                        )
                    });

            assert_eq!(parsed, direct);
            assert_eq!(parsed.program_type(), program_type);
        }
    }

    #[test]
    fn test_program_spec_display_round_trips_modeled_specs() {
        let mut specs = EbpfProgramType::supported_program_types()
            .iter()
            .map(|program_type| {
                let target = ProgramSpec::representative_target_for_program_type(*program_type);
                format!("{}:{target}", program_type.canonical_prefix())
            })
            .collect::<Vec<_>>();
        specs.extend([
            "fentry.s:security_file_open".to_string(),
            "fexit.s:security_file_open".to_string(),
            "fmod_ret.s:bpf_modify_return_test".to_string(),
            "lsm.s:file_open".to_string(),
            "uprobe.s:/bin/bash:main".to_string(),
            "uretprobe.s:/lib/libc.so.6:malloc".to_string(),
            "uprobe.multi.s:/bin/bash:read*".to_string(),
            "uretprobe.multi.s:/bin/bash:read*".to_string(),
            "struct_ops:sched_ext_ops.init".to_string(),
            "struct_ops:sched_ext_ops.select_cpu".to_string(),
        ]);

        for spec_text in specs {
            let spec = ProgramSpec::parse(&spec_text)
                .unwrap_or_else(|err| panic!("{spec_text} should parse before round trip: {err}"));
            let rendered = spec.to_string();
            let reparsed = ProgramSpec::parse(&rendered).unwrap_or_else(|err| {
                panic!("{spec_text} rendered as {rendered} should parse: {err}")
            });
            assert_eq!(reparsed, spec, "{spec_text} should round-trip via Display");
        }
    }

    #[test]
    fn test_struct_ops_target_parses_objects_and_callbacks() {
        let object = ProgramSpec::parse("struct_ops:sched_ext_ops")
            .expect("struct_ops object spec should parse");
        assert_eq!(
            object,
            ProgramSpec::StructOps {
                value_type_name: "sched_ext_ops".to_string(),
            }
        );
        assert_eq!(object.target_string(), "sched_ext_ops");
        assert_eq!(object.struct_ops_value_type_name(), Some("sched_ext_ops"));
        assert_eq!(object.struct_ops_callback_name(), None);
        assert_eq!(object.target_kind(), ProgramTargetKind::StructOpsValueType);
        assert_eq!(object.btf_callable_surface(), None);
        assert_eq!(object.arg_access(), ProgramValueAccess::None);
        assert_eq!(object.retval_access(), ProgramValueAccess::None);
        assert_eq!(object.section_name(), "struct_ops/sched_ext_ops");
        assert_eq!(object.to_string(), "struct_ops:sched_ext_ops");

        let callback = ProgramSpec::parse("struct_ops:sched_ext_ops.init")
            .expect("struct_ops callback spec should parse");
        assert_eq!(
            callback,
            ProgramSpec::StructOpsCallback {
                value_type_name: "sched_ext_ops".to_string(),
                callback_name: "init".to_string(),
            }
        );
        assert_eq!(callback.program_type(), EbpfProgramType::StructOps);
        assert_eq!(callback.target_string(), "init");
        assert_eq!(callback.struct_ops_value_type_name(), Some("sched_ext_ops"));
        assert_eq!(callback.struct_ops_callback_name(), Some("init"));
        assert_eq!(callback.target_kind(), ProgramTargetKind::StructOpsCallback);
        assert_eq!(
            callback.btf_callable_surface(),
            Some(ProgramBtfCallableSurface::StructOpsCallback)
        );
        assert_eq!(callback.arg_access(), ProgramValueAccess::Trampoline);
        assert_eq!(callback.retval_access(), ProgramValueAccess::None);
        assert_eq!(callback.section_name(), "struct_ops.s/init");
        assert_eq!(callback.to_string(), "struct_ops:sched_ext_ops.init");
        assert_eq!(
            callback.attach_shape(),
            ProgramAttachShape::StructOpsCallback {
                family: StructOpsFamily::SchedExt,
                sleepable: true,
            }
        );

        let select_cpu = ProgramSpec::from_program_type_target(
            EbpfProgramType::StructOps,
            "sched_ext_ops.select_cpu",
        )
        .expect("struct_ops callback target should parse directly");
        assert_eq!(select_cpu.section_name(), "struct_ops/select_cpu");
        assert_eq!(
            select_cpu.attach_shape(),
            ProgramAttachShape::StructOpsCallback {
                family: StructOpsFamily::SchedExt,
                sleepable: false,
            }
        );
    }

    #[test]
    fn test_struct_ops_target_rejects_empty_callback_parts() {
        let empty_target =
            ProgramSpec::parse("struct_ops:").expect_err("empty target should be rejected");
        assert_eq!(
            empty_target.to_string(),
            "struct_ops target requires a value type name"
        );

        let empty_value = ProgramSpec::parse("struct_ops:.init")
            .expect_err("empty callback value type should be rejected");
        assert_eq!(
            empty_value.to_string(),
            "struct_ops callback target requires a value type name before '.'"
        );

        let empty_callback = ProgramSpec::parse("struct_ops:sched_ext_ops.")
            .expect_err("empty callback name should be rejected");
        assert_eq!(
            empty_callback.to_string(),
            "struct_ops callback target requires a callback name after '.'"
        );
    }

    #[test]
    fn test_parse_matching_program_type_accepts_only_requested_program_type() {
        let xdp = ProgramSpec::parse_matching_program_type("xdp:lo:drv", EbpfProgramType::Xdp)
            .expect("matching xdp spec should parse");

        assert_eq!(xdp.program_type(), EbpfProgramType::Xdp);
        assert_eq!(xdp.target_string(), "lo:drv");
        assert_eq!(
            ProgramSpec::parse_matching_program_type("xdp:lo", EbpfProgramType::Kprobe),
            None
        );
        assert_eq!(
            ProgramSpec::parse_matching_program_type("lo", EbpfProgramType::Xdp),
            None
        );
    }

    #[test]
    fn test_cgroup_sysctl_target_requires_non_empty_path() {
        let target =
            CgroupSysctlTarget::parse("/sys/fs/cgroup").expect("cgroup_sysctl target should parse");
        assert_eq!(target.target_string(), "/sys/fs/cgroup");
        assert_eq!(target.section_name(), "cgroup/sysctl");

        let err =
            CgroupSysctlTarget::parse("").expect_err("empty cgroup_sysctl path should be rejected");
        assert_eq!(err.to_string(), "cgroup_sysctl cgroup path cannot be empty");
    }

    #[test]
    fn test_tc_action_target_requires_non_empty_label() {
        let target = TcActionTarget::parse("demo-action").expect("tc_action target should parse");
        assert_eq!(target.target_string(), "demo-action");

        let err = TcActionTarget::parse("").expect_err("empty tc_action label should be rejected");
        assert_eq!(err.to_string(), "tc_action target label cannot be empty");
    }

    #[test]
    fn test_extension_target_requires_non_empty_function() {
        let target = ExtensionTarget::parse("replace_me").expect("freplace target should parse");
        assert_eq!(target.target_string(), "replace_me");

        let err = ExtensionTarget::parse("").expect_err("empty freplace target should be rejected");
        assert_eq!(err.to_string(), "freplace target function cannot be empty");
    }

    #[test]
    fn test_syscall_target_requires_non_empty_label() {
        let target = SyscallTarget::parse("demo").expect("syscall target should parse");
        assert_eq!(target.target_string(), "demo");

        let err = SyscallTarget::parse("").expect_err("empty syscall target should be rejected");
        assert_eq!(err.to_string(), "syscall target label cannot be empty");
    }

    #[test]
    fn test_iter_target_requires_non_empty_name() {
        let target = IterTarget::parse("task").expect("BPF iterator target should parse");
        assert_eq!(target.target_string(), "task");

        let err = IterTarget::parse("").expect_err("empty BPF iterator target should be rejected");
        assert_eq!(err.to_string(), "BPF iterator target cannot be empty");
    }

    #[test]
    fn test_xdp_target_requires_non_empty_interface() {
        let target = XdpTarget::parse("lo").expect("xdp target should parse");
        assert_eq!(target.target_string(), "lo");
        assert_eq!(target.attach_mode, XdpAttachMode::Skb);
        assert!(!target.frags);
        assert_eq!(target.section_name(), "xdp");

        let frags = XdpTarget::parse("lo:frags").expect("xdp frags target should parse");
        assert_eq!(frags.interface, "lo");
        assert_eq!(frags.attach_mode, XdpAttachMode::Skb);
        assert!(frags.frags);
        assert_eq!(frags.target_string(), "lo:frags");
        assert_eq!(frags.section_name(), "xdp.frags");

        let driver = XdpTarget::parse("lo:native").expect("xdp native target should parse");
        assert_eq!(driver.interface, "lo");
        assert_eq!(driver.attach_mode, XdpAttachMode::Driver);
        assert!(!driver.frags);
        assert_eq!(driver.target_string(), "lo:drv");
        assert_eq!(driver.section_name(), "xdp");

        let hardware_frags =
            XdpTarget::parse("lo:frags:offload").expect("xdp hw frags target should parse");
        assert_eq!(hardware_frags.interface, "lo");
        assert_eq!(hardware_frags.attach_mode, XdpAttachMode::Hardware);
        assert!(hardware_frags.frags);
        assert_eq!(hardware_frags.target_string(), "lo:hw:frags");
        assert_eq!(hardware_frags.section_name(), "xdp.frags");

        let err = XdpTarget::parse("").expect_err("empty xdp interface should be rejected");
        assert_eq!(err.to_string(), "xdp interface target cannot be empty");

        let err =
            XdpTarget::parse("lo:native:hw").expect_err("duplicate xdp mode should be rejected");
        assert_eq!(
            err.to_string(),
            "xdp target accepts at most one attach mode"
        );

        let err = XdpTarget::parse("lo:wat").expect_err("unknown xdp option should be rejected");
        assert_eq!(
            err.to_string(),
            "Invalid xdp target option: wat. Expected format: interface[:skb|drv|hw][:frags]"
        );
    }

    #[test]
    fn test_netfilter_target_parses_and_validates_supported_bpf_shape() {
        let target =
            NetfilterTarget::parse("ipv4:pre_routing:prio=-200:defrag").expect("target parses");
        assert_eq!(target.family, NetfilterProtocolFamily::Ipv4);
        assert_eq!(target.hook, NetfilterHook::PreRouting);
        assert_eq!(target.priority, -200);
        assert!(target.defrag);
        assert_eq!(
            target.target_string(),
            "ipv4:pre_routing:priority=-200:defrag"
        );

        let ipv6 = NetfilterTarget::parse("ip6:localin").expect("ipv6 target parses");
        assert_eq!(ipv6.family, NetfilterProtocolFamily::Ipv6);
        assert_eq!(ipv6.hook, NetfilterHook::LocalIn);
        assert_eq!(ipv6.target_string(), "ipv6:local_in");

        let err = NetfilterTarget::parse("inet:pre_routing")
            .expect_err("unsupported BPF netfilter family should be rejected");
        assert_eq!(
            err.to_string(),
            "Invalid netfilter family: inet. Expected ipv4 or ipv6"
        );

        let err =
            NetfilterTarget::parse("ipv4:ingress").expect_err("unsupported hook should reject");
        assert_eq!(
            err.to_string(),
            "Invalid netfilter hook: ingress. Expected pre_routing, local_in, forward, local_out, or post_routing"
        );

        let err = NetfilterTarget::parse("ipv4:pre_routing:priority=-400:defrag")
            .expect_err("defrag before conntrack defrag should reject");
        assert_eq!(
            err.to_string(),
            "Invalid netfilter target: defrag requires priority greater than -400"
        );
    }

    #[test]
    fn test_lwt_target_requires_non_empty_label() {
        let target = LwtTarget::parse("demo-route").expect("lwt target should parse");
        assert_eq!(target.route, "demo-route");
        assert_eq!(target.target_string(), "demo-route");

        let err = LwtTarget::parse("").expect_err("empty lwt target should reject");
        assert_eq!(err.to_string(), "lwt target label cannot be empty");
    }

    #[test]
    fn test_xdp_frags_program_spec_uses_xdp_frags_section() {
        let spec = ProgramSpec::parse("xdp:lo:frags").expect("xdp frags spec should parse");
        assert_eq!(spec.to_string(), "xdp:lo:frags");
        assert_eq!(spec.section_name(), "xdp.frags");

        assert!(matches!(
            spec,
            ProgramSpec::Xdp {
                target: XdpTarget {
                    ref interface,
                    attach_mode: XdpAttachMode::Skb,
                    frags: true
                }
            } if interface == "lo"
        ));
    }
}
