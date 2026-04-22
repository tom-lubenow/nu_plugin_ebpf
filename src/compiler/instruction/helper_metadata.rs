use super::*;

#[path = "helper_metadata/semantics.rs"]
mod semantics;

impl BpfHelper {
    pub const fn from_u32(helper_id: u32) -> Option<Self> {
        match helper_id {
            1 => Some(Self::MapLookupElem),
            195 => Some(Self::MapLookupPercpuElem),
            2 => Some(Self::MapUpdateElem),
            3 => Some(Self::MapDeleteElem),
            4 => Some(Self::ProbeRead),
            112 => Some(Self::ProbeReadUser),
            113 => Some(Self::ProbeReadKernel),
            5 => Some(Self::KtimeGetNs),
            6 => Some(Self::TracePrintk),
            7 => Some(Self::GetPrandomU32),
            8 => Some(Self::GetSmpProcessorId),
            9 => Some(Self::SkbStoreBytes),
            10 => Some(Self::L3CsumReplace),
            11 => Some(Self::L4CsumReplace),
            33 => Some(Self::SkbUnderCgroup),
            34 => Some(Self::GetHashRecalc),
            35 => Some(Self::GetCurrentTask),
            37 => Some(Self::CurrentTaskUnderCgroup),
            38 => Some(Self::SkbChangeTail),
            39 => Some(Self::SkbPullData),
            40 => Some(Self::CsumUpdate),
            41 => Some(Self::SetHashInvalid),
            42 => Some(Self::GetNumaNodeId),
            48 => Some(Self::SetHash),
            43 => Some(Self::SkbChangeHead),
            44 => Some(Self::XdpAdjustHead),
            23 => Some(Self::Redirect),
            26 => Some(Self::SkbLoadBytes),
            51 => Some(Self::RedirectMap),
            152 => Some(Self::RedirectNeigh),
            155 => Some(Self::RedirectPeer),
            54 => Some(Self::XdpAdjustMeta),
            68 => Some(Self::SkbLoadBytesRelative),
            12 => Some(Self::TailCall),
            13 => Some(Self::CloneRedirect),
            14 => Some(Self::GetCurrentPidTgid),
            15 => Some(Self::GetCurrentUidGid),
            80 => Some(Self::GetCurrentCgroupId),
            123 => Some(Self::GetCurrentAncestorCgroupId),
            16 => Some(Self::GetCurrentComm),
            17 => Some(Self::GetCgroupClassid),
            18 => Some(Self::SkbVlanPush),
            19 => Some(Self::SkbVlanPop),
            20 => Some(Self::SkbGetTunnelKey),
            21 => Some(Self::SkbSetTunnelKey),
            24 => Some(Self::GetRouteRealm),
            61 => Some(Self::MsgApplyBytes),
            62 => Some(Self::MsgCorkBytes),
            63 => Some(Self::MsgPullData),
            64 => Some(Self::Bind),
            46 => Some(Self::GetSocketCookie),
            47 => Some(Self::GetSocketUid),
            50 => Some(Self::SkbAdjustRoom),
            192 => Some(Self::SkbSetTstamp),
            49 => Some(Self::SetSockOpt),
            52 => Some(Self::SkRedirectMap),
            53 => Some(Self::SockMapUpdate),
            56 => Some(Self::PerfProgReadValue),
            57 => Some(Self::GetSockOpt),
            59 => Some(Self::SockOpsCbFlagsSet),
            60 => Some(Self::MsgRedirectMap),
            79 => Some(Self::SkbCgroupId),
            83 => Some(Self::SkbAncestorCgroupId),
            122 => Some(Self::GetNetnsCookie),
            70 => Some(Self::SockHashUpdate),
            71 => Some(Self::MsgRedirectHash),
            72 => Some(Self::SkRedirectHash),
            82 => Some(Self::SkSelectReuseport),
            118 => Some(Self::Jiffies64),
            119 => Some(Self::ReadBranchRecords),
            125 => Some(Self::KtimeGetBootNs),
            160 => Some(Self::KtimeGetCoarseNs),
            163 => Some(Self::CheckMtu),
            173 => Some(Self::GetFuncIp),
            174 => Some(Self::GetAttachCookie),
            142 => Some(Self::LoadHdrOpt),
            143 => Some(Self::StoreHdrOpt),
            144 => Some(Self::ReserveHdrOpt),
            25 => Some(Self::PerfEventOutput),
            27 => Some(Self::GetStackId),
            67 => Some(Self::GetStack),
            28 => Some(Self::CsumDiff),
            29 => Some(Self::SkbGetTunnelOpt),
            30 => Some(Self::SkbSetTunnelOpt),
            69 => Some(Self::FibLookup),
            31 => Some(Self::SkbChangeProto),
            32 => Some(Self::SkbChangeType),
            84 => Some(Self::SkLookupTcp),
            85 => Some(Self::SkLookupUdp),
            86 => Some(Self::SkRelease),
            87 => Some(Self::MapPushElem),
            88 => Some(Self::MapPopElem),
            89 => Some(Self::MapPeekElem),
            90 => Some(Self::MsgPushData),
            91 => Some(Self::MsgPopData),
            65 => Some(Self::XdpAdjustTail),
            66 => Some(Self::SkbGetXfrmState),
            188 => Some(Self::XdpGetBuffLen),
            189 => Some(Self::XdpLoadBytes),
            190 => Some(Self::XdpStoreBytes),
            77 => Some(Self::RcRepeat),
            78 => Some(Self::RcKeydown),
            92 => Some(Self::RcPointerRel),
            95 => Some(Self::SkFullsock),
            96 => Some(Self::TcpSock),
            97 => Some(Self::SkbEcnSetCe),
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
            135 => Some(Self::CsumLevel),
            136 => Some(Self::SkcToTcp6Sock),
            137 => Some(Self::SkcToTcpSock),
            138 => Some(Self::SkcToTcpTimewaitSock),
            139 => Some(Self::SkcToTcpRequestSock),
            140 => Some(Self::SkcToUdp6Sock),
            145 => Some(Self::InodeStorageGet),
            146 => Some(Self::InodeStorageDelete),
            156 => Some(Self::TaskStorageGet),
            157 => Some(Self::TaskStorageDelete),
            158 => Some(Self::GetCurrentTaskBtf),
            162 => Some(Self::SockFromFile),
            175 => Some(Self::TaskPtRegs),
            183 => Some(Self::GetFuncArg),
            184 => Some(Self::GetFuncRet),
            185 => Some(Self::GetFuncArgCnt),
            178 => Some(Self::SkcToUnixSock),
            208 => Some(Self::KtimeGetTaiNs),
            210 => Some(Self::CgrpStorageGet),
            211 => Some(Self::CgrpStorageDelete),
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
            BpfHelper::MapLookupPercpuElem => HelperSignature {
                min_args: 3,
                max_args: 3,
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
            BpfHelper::SkbStoreBytes => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbLoadBytes => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbLoadBytesRelative => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::L3CsumReplace | BpfHelper::L4CsumReplace => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbUnderCgroup => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::CurrentTaskUnderCgroup => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbChangeTail | BpfHelper::SkbChangeHead | BpfHelper::SkbChangeProto => {
                HelperSignature {
                    min_args: 3,
                    max_args: 3,
                    arg_kinds: [P, S, S, S, S],
                    ret_kind: HelperRetKind::Scalar,
                }
            }
            BpfHelper::SkbChangeType => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbPullData => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::CloneRedirect | BpfHelper::SkbVlanPush => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbVlanPop => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetHashRecalc | BpfHelper::SetHashInvalid => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SetHash => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::CsumUpdate | BpfHelper::CsumLevel => HelperSignature {
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
            BpfHelper::SkbAdjustRoom => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbSetTstamp => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
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
            | BpfHelper::KtimeGetCoarseNs
            | BpfHelper::KtimeGetTaiNs
            | BpfHelper::Jiffies64
            | BpfHelper::GetPrandomU32
            | BpfHelper::GetSmpProcessorId
            | BpfHelper::GetNumaNodeId
            | BpfHelper::GetCurrentPidTgid
            | BpfHelper::GetCurrentUidGid
            | BpfHelper::GetCurrentCgroupId => HelperSignature {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetCurrentAncestorCgroupId => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetCurrentTask | BpfHelper::GetCurrentTaskBtf => HelperSignature {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::PointerNonNull,
            },
            BpfHelper::GetFuncIp | BpfHelper::GetAttachCookie => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::XdpAdjustHead | BpfHelper::XdpAdjustMeta | BpfHelper::XdpAdjustTail => {
                HelperSignature {
                    min_args: 2,
                    max_args: 2,
                    arg_kinds: [P, S, S, S, S],
                    ret_kind: HelperRetKind::Scalar,
                }
            }
            BpfHelper::XdpGetBuffLen => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::XdpLoadBytes | BpfHelper::XdpStoreBytes => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbGetXfrmState => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::Redirect => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RedirectMap => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
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
            BpfHelper::PerfProgReadValue => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::ReadBranchRecords => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SockOpsCbFlagsSet => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SockHashUpdate
            | BpfHelper::MsgRedirectHash
            | BpfHelper::SkRedirectHash
            | BpfHelper::SkSelectReuseport => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
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
            BpfHelper::SkbCgroupId => HelperSignature {
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
            BpfHelper::SkbAncestorCgroupId => HelperSignature {
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
            BpfHelper::GetCgroupClassid | BpfHelper::GetRouteRealm | BpfHelper::SkbEcnSetCe => {
                HelperSignature {
                    min_args: 1,
                    max_args: 1,
                    arg_kinds: [P, S, S, S, S],
                    ret_kind: HelperRetKind::Scalar,
                }
            }
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
            BpfHelper::GetStack => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::CsumDiff => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbGetTunnelKey | BpfHelper::SkbSetTunnelKey => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkbGetTunnelOpt | BpfHelper::SkbSetTunnelOpt => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::FibLookup => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::CheckMtu => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, P, S, S],
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
            BpfHelper::CgrpStorageGet => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::CgrpStorageDelete => HelperSignature {
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
            BpfHelper::GetFuncArg => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetFuncRet => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetFuncArgCnt => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
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
            BpfHelper::SkbChangeTail => Some((2, "helper 'bpf_skb_change_tail' requires arg2 = 0")),
            BpfHelper::SkbChangeHead => Some((2, "helper 'bpf_skb_change_head' requires arg2 = 0")),
            BpfHelper::SkbChangeProto => {
                Some((2, "helper 'bpf_skb_change_proto' requires arg2 = 0"))
            }
            BpfHelper::RedirectNeigh => Some((3, "helper 'bpf_redirect_neigh' requires arg3 = 0")),
            BpfHelper::RedirectPeer => Some((1, "helper 'bpf_redirect_peer' requires arg1 = 0")),
            BpfHelper::SkbGetXfrmState => {
                Some((4, "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"))
            }
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
            BpfHelper::SkbSetTstamp => Some((
                1,
                2,
                "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0",
            )),
            _ => None,
        }
    }
}
