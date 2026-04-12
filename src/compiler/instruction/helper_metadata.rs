use super::*;

#[path = "helper_metadata/semantics.rs"]
mod semantics;

impl BpfHelper {
    pub const fn from_u32(helper_id: u32) -> Option<Self> {
        match helper_id {
            1 => Some(Self::MapLookupElem),
            2 => Some(Self::MapUpdateElem),
            3 => Some(Self::MapDeleteElem),
            4 => Some(Self::ProbeRead),
            112 => Some(Self::ProbeReadUser),
            113 => Some(Self::ProbeReadKernel),
            5 => Some(Self::KtimeGetNs),
            6 => Some(Self::TracePrintk),
            7 => Some(Self::GetPrandomU32),
            8 => Some(Self::GetSmpProcessorId),
            23 => Some(Self::Redirect),
            152 => Some(Self::RedirectNeigh),
            155 => Some(Self::RedirectPeer),
            12 => Some(Self::TailCall),
            14 => Some(Self::GetCurrentPidTgid),
            15 => Some(Self::GetCurrentUidGid),
            80 => Some(Self::GetCurrentCgroupId),
            16 => Some(Self::GetCurrentComm),
            61 => Some(Self::MsgApplyBytes),
            62 => Some(Self::MsgCorkBytes),
            63 => Some(Self::MsgPullData),
            64 => Some(Self::Bind),
            46 => Some(Self::GetSocketCookie),
            47 => Some(Self::GetSocketUid),
            49 => Some(Self::SetSockOpt),
            52 => Some(Self::SkRedirectMap),
            53 => Some(Self::SockMapUpdate),
            57 => Some(Self::GetSockOpt),
            59 => Some(Self::SockOpsCbFlagsSet),
            60 => Some(Self::MsgRedirectMap),
            122 => Some(Self::GetNetnsCookie),
            70 => Some(Self::SockHashUpdate),
            71 => Some(Self::MsgRedirectHash),
            72 => Some(Self::SkRedirectHash),
            125 => Some(Self::KtimeGetBootNs),
            142 => Some(Self::LoadHdrOpt),
            143 => Some(Self::StoreHdrOpt),
            144 => Some(Self::ReserveHdrOpt),
            25 => Some(Self::PerfEventOutput),
            27 => Some(Self::GetStackId),
            84 => Some(Self::SkLookupTcp),
            85 => Some(Self::SkLookupUdp),
            86 => Some(Self::SkRelease),
            87 => Some(Self::MapPushElem),
            88 => Some(Self::MapPopElem),
            89 => Some(Self::MapPeekElem),
            90 => Some(Self::MsgPushData),
            91 => Some(Self::MsgPopData),
            77 => Some(Self::RcRepeat),
            78 => Some(Self::RcKeydown),
            92 => Some(Self::RcPointerRel),
            95 => Some(Self::SkFullsock),
            96 => Some(Self::TcpSock),
            98 => Some(Self::GetListenerSock),
            99 => Some(Self::SkcLookupTcp),
            100 => Some(Self::TcpCheckSyncookie),
            101 => Some(Self::SysctlGetName),
            102 => Some(Self::SysctlGetCurrentValue),
            103 => Some(Self::SysctlGetNewValue),
            104 => Some(Self::SysctlSetNewValue),
            107 => Some(Self::SkStorageGet),
            108 => Some(Self::SkStorageDelete),
            110 => Some(Self::TcpGenSyncookie),
            124 => Some(Self::SkAssign),
            128 => Some(Self::SkCgroupId),
            129 => Some(Self::SkAncestorCgroupId),
            136 => Some(Self::SkcToTcp6Sock),
            137 => Some(Self::SkcToTcpSock),
            138 => Some(Self::SkcToTcpTimewaitSock),
            139 => Some(Self::SkcToTcpRequestSock),
            140 => Some(Self::SkcToUdp6Sock),
            145 => Some(Self::InodeStorageGet),
            146 => Some(Self::InodeStorageDelete),
            156 => Some(Self::TaskStorageGet),
            157 => Some(Self::TaskStorageDelete),
            162 => Some(Self::SockFromFile),
            175 => Some(Self::TaskPtRegs),
            178 => Some(Self::SkcToUnixSock),
            114 => Some(Self::ProbeReadUserStr),
            115 => Some(Self::ProbeReadKernelStr),
            130 => Some(Self::RingbufOutput),
            131 => Some(Self::RingbufReserve),
            132 => Some(Self::RingbufSubmit),
            133 => Some(Self::RingbufDiscard),
            134 => Some(Self::RingbufQuery),
            194 => Some(Self::KptrXchg),
            _ => None,
        }
    }

    pub const fn signature(self) -> HelperSignature {
        const S: HelperArgKind = HelperArgKind::Scalar;
        const P: HelperArgKind = HelperArgKind::Pointer;
        match self {
            BpfHelper::MapLookupElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::MapUpdateElem => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapDeleteElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapPushElem => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapPopElem | BpfHelper::MapPeekElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MsgApplyBytes | BpfHelper::MsgCorkBytes => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MsgPullData | BpfHelper::MsgPushData | BpfHelper::MsgPopData => {
                HelperSignature {
                    min_args: 4,
                    max_args: 4,
                    arg_kinds: [P, S, S, S, S],
                    ret_kind: HelperRetKind::Scalar,
                }
            }
            BpfHelper::Bind => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::ProbeRead | BpfHelper::ProbeReadUser | BpfHelper::ProbeReadKernel => {
                HelperSignature {
                    min_args: 3,
                    max_args: 3,
                    arg_kinds: [P, S, P, S, S],
                    ret_kind: HelperRetKind::Scalar,
                }
            }
            BpfHelper::KtimeGetNs
            | BpfHelper::KtimeGetBootNs
            | BpfHelper::GetPrandomU32
            | BpfHelper::GetSmpProcessorId
            | BpfHelper::GetCurrentPidTgid
            | BpfHelper::GetCurrentUidGid
            | BpfHelper::GetCurrentCgroupId => HelperSignature {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::Redirect => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RedirectNeigh => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [S, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RedirectPeer => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetSocketCookie => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetSocketUid => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkRedirectMap | BpfHelper::MsgRedirectMap => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SockMapUpdate => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SetSockOpt | BpfHelper::GetSockOpt => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, S, P, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SockOpsCbFlagsSet => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SockHashUpdate | BpfHelper::MsgRedirectHash | BpfHelper::SkRedirectHash => {
                HelperSignature {
                    min_args: 4,
                    max_args: 4,
                    arg_kinds: [P, P, P, S, S],
                    ret_kind: HelperRetKind::Scalar,
                }
            }
            BpfHelper::LoadHdrOpt | BpfHelper::StoreHdrOpt => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::ReserveHdrOpt => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkCgroupId => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkAncestorCgroupId => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetNetnsCookie => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RcRepeat => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RcKeydown => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RcPointerRel => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TracePrintk => HelperSignature {
                min_args: 2,
                max_args: 5,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TailCall => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetCurrentComm => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::PerfEventOutput => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, P, S, P, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetStackId => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
                HelperSignature {
                    min_args: 5,
                    max_args: 5,
                    arg_kinds: [P, P, S, S, S],
                    ret_kind: HelperRetKind::PointerMaybeNull,
                }
            }
            BpfHelper::TcpCheckSyncookie | BpfHelper::TcpGenSyncookie => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, P, S, P, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SysctlGetName => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SysctlGetCurrentValue
            | BpfHelper::SysctlGetNewValue
            | BpfHelper::SysctlSetNewValue => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkAssign => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkStorageGet => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::SkStorageDelete => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TaskStorageGet => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::TaskStorageDelete => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::InodeStorageGet => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::InodeStorageDelete => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SockFromFile => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::TaskPtRegs => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::SkRelease => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkFullsock
            | BpfHelper::TcpSock
            | BpfHelper::SkcToTcp6Sock
            | BpfHelper::SkcToTcpSock
            | BpfHelper::SkcToTcpTimewaitSock
            | BpfHelper::SkcToTcpRequestSock
            | BpfHelper::SkcToUdp6Sock
            | BpfHelper::SkcToUnixSock => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::GetListenerSock => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::RingbufOutput => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RingbufReserve => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::RingbufQuery => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::KptrXchg => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::ProbeReadUserStr | BpfHelper::ProbeReadKernelStr => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
        }
    }

    pub const fn zero_scalar_arg_requirement(self) -> Option<(usize, &'static str)> {
        match self {
            BpfHelper::RedirectNeigh => Some((3, "helper 'bpf_redirect_neigh' requires arg3 = 0")),
            BpfHelper::RedirectPeer => Some((1, "helper 'bpf_redirect_peer' requires arg1 = 0")),
            BpfHelper::StoreHdrOpt => Some((3, "helper 'bpf_store_hdr_opt' requires arg3 = 0")),
            BpfHelper::ReserveHdrOpt => Some((2, "helper 'bpf_reserve_hdr_opt' requires arg2 = 0")),
            _ => None,
        }
    }

    pub const fn zero_scalar_arg_requirement_when_arg_zero(
        self,
    ) -> Option<(usize, usize, &'static str)> {
        match self {
            BpfHelper::RedirectNeigh => Some((
                2,
                1,
                "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null",
            )),
            _ => None,
        }
    }
}
