use super::{EbpfProgramType, ProgramReturnAlias};

impl EbpfProgramType {
    pub(crate) fn return_action_alias(&self, alias: &str) -> Option<ProgramReturnAlias> {
        let alias = alias.to_ascii_lowercase();

        match self {
            EbpfProgramType::Xdp => match alias.as_str() {
                "abort" | "aborted" => Some(ProgramReturnAlias::Const(0)),
                "drop" => Some(ProgramReturnAlias::Const(1)),
                "pass" => Some(ProgramReturnAlias::Const(2)),
                "tx" => Some(ProgramReturnAlias::Const(3)),
                "redirect" => Some(ProgramReturnAlias::Const(4)),
                _ => None,
            },
            EbpfProgramType::SocketFilter => match alias.as_str() {
                "deny" | "drop" | "reject" => Some(ProgramReturnAlias::Const(0)),
                "allow" | "accept" | "permit" | "keep" | "pass" => {
                    Some(ProgramReturnAlias::PacketLen)
                }
                _ => None,
            },
            EbpfProgramType::Tc => match alias.as_str() {
                "ok" => Some(ProgramReturnAlias::Const(0)),
                "reclassify" => Some(ProgramReturnAlias::Const(1)),
                "shot" | "drop" => Some(ProgramReturnAlias::Const(2)),
                "pipe" => Some(ProgramReturnAlias::Const(3)),
                "stolen" => Some(ProgramReturnAlias::Const(4)),
                "queued" => Some(ProgramReturnAlias::Const(5)),
                "repeat" => Some(ProgramReturnAlias::Const(6)),
                "redirect" => Some(ProgramReturnAlias::Const(7)),
                "trap" => Some(ProgramReturnAlias::Const(8)),
                _ => None,
            },
            EbpfProgramType::CgroupSkb
            | EbpfProgramType::CgroupDevice
            | EbpfProgramType::CgroupSock
            | EbpfProgramType::CgroupSysctl
            | EbpfProgramType::CgroupSockopt
            | EbpfProgramType::CgroupSockAddr
            | EbpfProgramType::SkLookup
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkMsg => match alias.as_str() {
                "deny" | "drop" | "reject" => Some(ProgramReturnAlias::Const(0)),
                "allow" | "pass" | "accept" | "permit" => Some(ProgramReturnAlias::Const(1)),
                _ => None,
            },
            _ => None,
        }
    }
}
