use super::{EbpfProgramType, ProgramReturnAlias};

#[derive(Debug, Clone, Copy)]
struct ReturnActionAliasEntry {
    alias: &'static str,
    value: ProgramReturnAlias,
}

struct ReturnActionAliasSurface {
    program_types: &'static [EbpfProgramType],
    entries: &'static [ReturnActionAliasEntry],
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

const TCX_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "next",
        value: ProgramReturnAlias::Const(-1),
    },
    ReturnActionAliasEntry {
        alias: "pass",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "ok",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "redirect",
        value: ProgramReturnAlias::Const(7),
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

const FLOW_DISSECTOR_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "ok",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "parsed",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "continue",
        value: ProgramReturnAlias::Const(129),
    },
    ReturnActionAliasEntry {
        alias: "fallback",
        value: ProgramReturnAlias::Const(129),
    },
];

const NETFILTER_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "deny",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "accept",
        value: ProgramReturnAlias::Const(1),
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
        alias: "ok",
        value: ProgramReturnAlias::Const(1),
    },
    ReturnActionAliasEntry {
        alias: "stolen",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "queue",
        value: ProgramReturnAlias::Const(3),
    },
    ReturnActionAliasEntry {
        alias: "repeat",
        value: ProgramReturnAlias::Const(4),
    },
];

const LWT_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "ok",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "pass",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "redirect",
        value: ProgramReturnAlias::Const(7),
    },
];

const LWT_REROUTE_RETURN_ALIAS_ENTRIES: &[ReturnActionAliasEntry] = &[
    ReturnActionAliasEntry {
        alias: "ok",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "pass",
        value: ProgramReturnAlias::Const(0),
    },
    ReturnActionAliasEntry {
        alias: "drop",
        value: ProgramReturnAlias::Const(2),
    },
    ReturnActionAliasEntry {
        alias: "redirect",
        value: ProgramReturnAlias::Const(7),
    },
    ReturnActionAliasEntry {
        alias: "reroute",
        value: ProgramReturnAlias::Const(128),
    },
];

const XDP_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Xdp];

const SOCKET_FILTER_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SocketFilter];

const TC_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::Tc, EbpfProgramType::TcAction];

const TCX_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::Tcx, EbpfProgramType::Netkit];

const FLOW_DISSECTOR_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::FlowDissector];

const NETFILTER_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Netfilter];

const LWT_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::LwtOut, EbpfProgramType::LwtSeg6Local];

const LWT_REROUTE_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::LwtIn, EbpfProgramType::LwtXmit];

const ALLOW_DENY_RETURN_ALIAS_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupDevice,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSysctl,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::LsmCgroup,
    EbpfProgramType::SkLookup,
    EbpfProgramType::SkReuseport,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkMsg,
];

const RETURN_ACTION_ALIAS_SURFACES: &[ReturnActionAliasSurface] = &[
    ReturnActionAliasSurface {
        program_types: XDP_RETURN_ALIAS_PROGRAMS,
        entries: XDP_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: SOCKET_FILTER_RETURN_ALIAS_PROGRAMS,
        entries: SOCKET_FILTER_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: TC_RETURN_ALIAS_PROGRAMS,
        entries: TC_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: TCX_RETURN_ALIAS_PROGRAMS,
        entries: TCX_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: FLOW_DISSECTOR_RETURN_ALIAS_PROGRAMS,
        entries: FLOW_DISSECTOR_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: NETFILTER_RETURN_ALIAS_PROGRAMS,
        entries: NETFILTER_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: LWT_REROUTE_RETURN_ALIAS_PROGRAMS,
        entries: LWT_REROUTE_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: LWT_RETURN_ALIAS_PROGRAMS,
        entries: LWT_RETURN_ALIAS_ENTRIES,
    },
    ReturnActionAliasSurface {
        program_types: ALLOW_DENY_RETURN_ALIAS_PROGRAMS,
        entries: ALLOW_DENY_RETURN_ALIAS_ENTRIES,
    },
];

impl EbpfProgramType {
    fn return_action_alias_entries(&self) -> Option<&'static [ReturnActionAliasEntry]> {
        RETURN_ACTION_ALIAS_SURFACES
            .iter()
            .find(|surface| surface.program_types.contains(self))
            .map(|surface| surface.entries)
    }

    pub(crate) fn return_action_alias(&self, alias: &str) -> Option<ProgramReturnAlias> {
        let alias = alias.to_ascii_lowercase();
        self.return_action_alias_entries()?
            .iter()
            .find(|entry| entry.alias == alias)
            .map(|entry| entry.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_return_action_alias_surfaces_are_unique() {
        let mut surfaced_program_types = HashSet::new();

        for (index, surface) in RETURN_ACTION_ALIAS_SURFACES.iter().enumerate() {
            let mut aliases = HashSet::new();
            for entry in surface.entries {
                assert_eq!(
                    entry.alias,
                    entry.alias.to_ascii_lowercase(),
                    "return alias '{}' in surface #{index} must be lowercase",
                    entry.alias
                );
                assert!(
                    aliases.insert(entry.alias),
                    "duplicate return alias '{}' in surface #{index}",
                    entry.alias
                );
            }

            let mut local_program_types = HashSet::new();
            for program_type in surface.program_types {
                assert!(
                    local_program_types.insert(*program_type),
                    "duplicate program type {program_type:?} in return alias surface #{index}"
                );
                assert!(
                    surfaced_program_types.insert(*program_type),
                    "program type {program_type:?} appears in multiple return alias surfaces"
                );
            }
        }
    }
}
