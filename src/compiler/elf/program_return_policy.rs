use super::{EbpfProgramType, ProgramReturnAlias};

#[derive(Debug, Clone, Copy)]
struct ReturnActionAliasEntry {
    alias: &'static str,
    value: ProgramReturnAlias,
}

const XDP_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "abort",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "aborted",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(1),
    },
    ReturnActionAliasEntry {
        alias: "pass",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "tx",
        value: ProgramReturnAlias::Const(3),
    },
    ReturnActionAliasEntry {
        alias: "redirect",
        value: ProgramReturnAlias::Const(4),
    },
];

const SOCKET_FILTER_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "deny",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "reject",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "allow",
        value: ProgramReturnAlias::PacketLen,
    },
    ReturnActionAliasEntry {
        alias: "accept",
        value: ProgramReturnAlias::PacketLen,
    },
    ReturnActionAliasEntry {
        alias: "permit",
        value: ProgramReturnAlias::PacketLen,
    },
    ReturnActionAliasEntry {
        alias: "keep",
        value: ProgramReturnAlias::PacketLen,
    },
    ReturnActionAliasEntry {
        alias: "pass",
        value: ProgramReturnAlias::PacketLen,
    },
];

const TC_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "ok",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "reclassify",
        value: ProgramReturnAlias::Const(1),
    },
    ReturnActionAliasEntry {
        alias: "shot",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "pipe",
        value: ProgramReturnAlias::Const(3),
    },
    ReturnActionAliasEntry {
        alias: "stolen",
        value: ProgramReturnAlias::Const(4),
    },
    ReturnActionAliasEntry {
        alias: "queued",
        value: ProgramReturnAlias::Const(5),
    },
    ReturnActionAliasEntry {
        alias: "repeat",
        value: ProgramReturnAlias::Const(6),
    },
    ReturnActionAliasEntry {
        alias: "redirect",
        value: ProgramReturnAlias::Const(7),
    },
    ReturnActionAliasEntry {
        alias: "trap",
        value: ProgramReturnAlias::Const(8),
    },
];

const ALLOW_DENY_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "deny",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "reject",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "allow",
        value: ProgramReturnAlias::Const(1),
    },
    ReturnActionAliasEntry {
        alias: "pass",
        value: ProgramReturnAlias::Const(1),
    },
    ReturnActionAliasEntry {
        alias: "accept",
        value: ProgramReturnAlias::Const(1),
    },
    ReturnActionAliasEntry {
        alias: "permit",
        value: ProgramReturnAlias::Const(1),
    },
];

impl EbpfProgramType {
    fn return_action_alias_entries(&self) -> Option<&'static [ReturnActionAliasEntry]> {
        match self {
            EbpfProgramType::Xdp => Some(XDP_RETURN_ALIAS_ENTRIES),
            EbpfProgramType::SocketFilter => Some(SOCKET_FILTER_RETURN_ALIAS_ENTRIES),
            EbpfProgramType::Tc => Some(TC_RETURN_ALIAS_ENTRIES),
            EbpfProgramType::CgroupSkb
            | EbpfProgramType::CgroupDevice
            | EbpfProgramType::CgroupSock
            | EbpfProgramType::CgroupSysctl
            | EbpfProgramType::CgroupSockopt
            | EbpfProgramType::CgroupSockAddr
            | EbpfProgramType::SkLookup
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkMsg => Some(ALLOW_DENY_RETURN_ALIAS_ENTRIES),
            _ => None,
        }
    }

    pub(crate) fn return_action_alias(&self, alias: &str) -> Option<ProgramReturnAlias> {
        let alias = alias.to_ascii_lowercase();
        self.return_action_alias_entries()?
            .iter()
            .find(|entry| entry.alias == alias)
            .map(|entry| entry.value)
    }
}
