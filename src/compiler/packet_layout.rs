use super::mir::{BitfieldInfo, MirType, StructField};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PacketHeaderKind {
    Ethernet,
    Ipv4,
    Ipv6,
    Udp,
    Icmp,
    Icmpv6,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PacketHeaderFieldType {
    U8,
    U16,
    U32,
    Bytes(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PacketHeaderBitfieldSpec {
    pub bit_offset: u32,
    pub bit_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PacketHeaderFieldSpec {
    pub name: &'static str,
    pub ty: PacketHeaderFieldType,
    pub offset: usize,
    pub bitfield: Option<PacketHeaderBitfieldSpec>,
    pub big_endian: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PacketHeaderProtocolView {
    pub from: PacketHeaderKind,
    pub to: PacketHeaderKind,
}

const fn packet_field(
    name: &'static str,
    ty: PacketHeaderFieldType,
    offset: usize,
    big_endian: bool,
) -> PacketHeaderFieldSpec {
    PacketHeaderFieldSpec {
        name,
        ty,
        offset,
        bitfield: None,
        big_endian,
    }
}

const fn packet_bitfield(
    name: &'static str,
    ty: PacketHeaderFieldType,
    offset: usize,
    bit_offset: u32,
    bit_size: u32,
    big_endian: bool,
) -> PacketHeaderFieldSpec {
    PacketHeaderFieldSpec {
        name,
        ty,
        offset,
        bitfield: Some(PacketHeaderBitfieldSpec {
            bit_offset,
            bit_size,
        }),
        big_endian,
    }
}

const fn protocol_view(from: PacketHeaderKind, to: PacketHeaderKind) -> PacketHeaderProtocolView {
    PacketHeaderProtocolView { from, to }
}

const ALL_PACKET_HEADERS: &[PacketHeaderKind] = &[
    PacketHeaderKind::Ethernet,
    PacketHeaderKind::Ipv4,
    PacketHeaderKind::Ipv6,
    PacketHeaderKind::Udp,
    PacketHeaderKind::Icmp,
    PacketHeaderKind::Icmpv6,
    PacketHeaderKind::Tcp,
];

const PACKET_PROTOCOL_VIEWS: &[PacketHeaderProtocolView] = &[
    protocol_view(PacketHeaderKind::Ethernet, PacketHeaderKind::Ipv4),
    protocol_view(PacketHeaderKind::Ethernet, PacketHeaderKind::Ipv6),
    protocol_view(PacketHeaderKind::Ipv4, PacketHeaderKind::Udp),
    protocol_view(PacketHeaderKind::Ipv4, PacketHeaderKind::Icmp),
    protocol_view(PacketHeaderKind::Ipv4, PacketHeaderKind::Tcp),
    protocol_view(PacketHeaderKind::Ipv6, PacketHeaderKind::Udp),
    protocol_view(PacketHeaderKind::Ipv6, PacketHeaderKind::Icmpv6),
    protocol_view(PacketHeaderKind::Ipv6, PacketHeaderKind::Tcp),
];

const ETHERNET_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("dst", PacketHeaderFieldType::Bytes(6), 0, false),
    packet_field("src", PacketHeaderFieldType::Bytes(6), 6, false),
    packet_field("ethertype", PacketHeaderFieldType::U16, 12, true),
];

const IPV4_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("version_ihl", PacketHeaderFieldType::U8, 0, false),
    packet_bitfield("ihl", PacketHeaderFieldType::U8, 0, 0, 4, false),
    packet_bitfield("version", PacketHeaderFieldType::U8, 0, 4, 4, false),
    packet_field("dscp_ecn", PacketHeaderFieldType::U8, 1, false),
    packet_bitfield("ecn", PacketHeaderFieldType::U8, 1, 0, 2, false),
    packet_bitfield("dscp", PacketHeaderFieldType::U8, 1, 2, 6, false),
    packet_field("total_len", PacketHeaderFieldType::U16, 2, true),
    packet_field("identification", PacketHeaderFieldType::U16, 4, true),
    packet_field("flags_fragment_offset", PacketHeaderFieldType::U16, 6, true),
    packet_field("ttl", PacketHeaderFieldType::U8, 8, false),
    packet_field("protocol", PacketHeaderFieldType::U8, 9, false),
    packet_field("checksum", PacketHeaderFieldType::U16, 10, true),
    packet_field("src", PacketHeaderFieldType::Bytes(4), 12, false),
    packet_field("dst", PacketHeaderFieldType::Bytes(4), 16, false),
];

const IPV6_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("version_tc_flow_label", PacketHeaderFieldType::U32, 0, true),
    packet_bitfield("flow_label", PacketHeaderFieldType::U32, 0, 0, 20, true),
    packet_bitfield("traffic_class", PacketHeaderFieldType::U32, 0, 20, 8, true),
    packet_bitfield("version", PacketHeaderFieldType::U32, 0, 28, 4, true),
    packet_field("payload_len", PacketHeaderFieldType::U16, 4, true),
    packet_field("next_header", PacketHeaderFieldType::U8, 6, false),
    packet_field("hop_limit", PacketHeaderFieldType::U8, 7, false),
    packet_field("src", PacketHeaderFieldType::Bytes(16), 8, false),
    packet_field("dst", PacketHeaderFieldType::Bytes(16), 24, false),
];

const UDP_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("src", PacketHeaderFieldType::U16, 0, true),
    packet_field("dst", PacketHeaderFieldType::U16, 2, true),
    packet_field("len", PacketHeaderFieldType::U16, 4, true),
    packet_field("checksum", PacketHeaderFieldType::U16, 6, true),
];

const ICMP_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("type", PacketHeaderFieldType::U8, 0, false),
    packet_field("code", PacketHeaderFieldType::U8, 1, false),
    packet_field("checksum", PacketHeaderFieldType::U16, 2, true),
    packet_field("body", PacketHeaderFieldType::Bytes(4), 4, false),
];

const ICMPV6_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("type", PacketHeaderFieldType::U8, 0, false),
    packet_field("code", PacketHeaderFieldType::U8, 1, false),
    packet_field("checksum", PacketHeaderFieldType::U16, 2, true),
    packet_field("body", PacketHeaderFieldType::Bytes(4), 4, false),
];

const TCP_FIELDS: &[PacketHeaderFieldSpec] = &[
    packet_field("src", PacketHeaderFieldType::U16, 0, true),
    packet_field("dst", PacketHeaderFieldType::U16, 2, true),
    packet_field("seq", PacketHeaderFieldType::U32, 4, true),
    packet_field("ack_seq", PacketHeaderFieldType::U32, 8, true),
    packet_field("data_offset_flags", PacketHeaderFieldType::U16, 12, true),
    packet_bitfield("ns", PacketHeaderFieldType::U8, 12, 0, 1, false),
    packet_bitfield("reserved", PacketHeaderFieldType::U8, 12, 1, 3, false),
    packet_bitfield("data_offset", PacketHeaderFieldType::U8, 12, 4, 4, false),
    packet_field("flags", PacketHeaderFieldType::U8, 13, false),
    packet_bitfield("fin", PacketHeaderFieldType::U8, 13, 0, 1, false),
    packet_bitfield("syn", PacketHeaderFieldType::U8, 13, 1, 1, false),
    packet_bitfield("rst", PacketHeaderFieldType::U8, 13, 2, 1, false),
    packet_bitfield("psh", PacketHeaderFieldType::U8, 13, 3, 1, false),
    packet_bitfield("ack", PacketHeaderFieldType::U8, 13, 4, 1, false),
    packet_bitfield("urg", PacketHeaderFieldType::U8, 13, 5, 1, false),
    packet_bitfield("ece", PacketHeaderFieldType::U8, 13, 6, 1, false),
    packet_bitfield("cwr", PacketHeaderFieldType::U8, 13, 7, 1, false),
    packet_field("window", PacketHeaderFieldType::U16, 14, true),
    packet_field("checksum", PacketHeaderFieldType::U16, 16, true),
    packet_field("urg_ptr", PacketHeaderFieldType::U16, 18, true),
];

impl PacketHeaderFieldType {
    pub(crate) fn mir_type(self) -> MirType {
        match self {
            Self::U8 => MirType::U8,
            Self::U16 => MirType::U16,
            Self::U32 => MirType::U32,
            Self::Bytes(len) => MirType::Array {
                elem: Box::new(MirType::U8),
                len,
            },
        }
    }
}

impl PacketHeaderFieldSpec {
    pub(crate) fn struct_field(self) -> StructField {
        StructField {
            name: self.name.to_string(),
            ty: self.ty.mir_type(),
            offset: self.offset,
            synthetic: false,
            bitfield: self.bitfield.map(|bitfield| BitfieldInfo {
                bit_offset: bitfield.bit_offset,
                bit_size: bitfield.bit_size,
            }),
        }
    }
}

impl PacketHeaderKind {
    pub(crate) fn all() -> &'static [Self] {
        ALL_PACKET_HEADERS
    }

    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Ethernet => "eth",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
            Self::Tcp => "tcp",
        }
    }

    pub(crate) fn type_name(self) -> &'static str {
        match self {
            Self::Ethernet => "__packet_eth",
            Self::Ipv4 => "__packet_ipv4",
            Self::Ipv6 => "__packet_ipv6",
            Self::Udp => "__packet_udp",
            Self::Icmp => "__packet_icmp",
            Self::Icmpv6 => "__packet_icmpv6",
            Self::Tcp => "__packet_tcp",
        }
    }

    pub(crate) fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Ethernet => &["eth", "ethhdr"],
            Self::Ipv4 => &["ipv4", "iphdr"],
            Self::Ipv6 => &["ipv6", "ipv6hdr", "ip6hdr"],
            Self::Udp => &["udp", "udphdr"],
            Self::Icmp => &["icmp", "icmphdr"],
            Self::Icmpv6 => &["icmpv6", "icmp6", "icmpv6hdr", "icmp6hdr"],
            Self::Tcp => &["tcp", "tcphdr"],
        }
    }

    pub(crate) fn fields(self) -> &'static [PacketHeaderFieldSpec] {
        match self {
            Self::Ethernet => ETHERNET_FIELDS,
            Self::Ipv4 => IPV4_FIELDS,
            Self::Ipv6 => IPV6_FIELDS,
            Self::Udp => UDP_FIELDS,
            Self::Icmp => ICMP_FIELDS,
            Self::Icmpv6 => ICMPV6_FIELDS,
            Self::Tcp => TCP_FIELDS,
        }
    }

    pub(crate) fn field(self, name: &str) -> Option<PacketHeaderFieldSpec> {
        self.fields()
            .iter()
            .copied()
            .find(|field| field.name == name)
    }

    pub(crate) fn protocol_views(self) -> impl Iterator<Item = PacketHeaderProtocolView> {
        PACKET_PROTOCOL_VIEWS
            .iter()
            .copied()
            .filter(move |view| view.from == self)
    }

    pub(crate) fn protocol_view_target(self, alias: &str) -> Option<Self> {
        let target = Self::from_alias(alias)?;
        self.protocol_views()
            .any(|view| view.to == target)
            .then_some(target)
    }

    pub(crate) fn supports_payload_step(self) -> bool {
        true
    }

    pub(crate) fn from_type_name(name: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|kind| kind.type_name() == name)
    }

    pub(crate) fn from_alias(alias: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|kind| kind.aliases().contains(&alias))
    }

    pub(crate) fn mir_type(self) -> MirType {
        MirType::Struct {
            name: Some(self.type_name().to_string()),
            kernel_btf_type_id: None,
            fields: self
                .fields()
                .iter()
                .copied()
                .map(PacketHeaderFieldSpec::struct_field)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn packet_header_aliases_are_unique_and_resolve() {
        let mut aliases = HashSet::new();
        for header in PacketHeaderKind::all() {
            for alias in header.aliases() {
                assert!(
                    aliases.insert(*alias),
                    "packet header alias {alias:?} should be unique"
                );
                assert_eq!(
                    PacketHeaderKind::from_alias(alias),
                    Some(*header),
                    "packet header alias {alias:?} should resolve to {header:?}"
                );
            }
        }
    }

    #[test]
    fn packet_header_fields_are_unique_within_header() {
        for header in PacketHeaderKind::all() {
            let mut fields = HashSet::new();
            for field in header.fields() {
                assert!(
                    fields.insert(field.name),
                    "packet header {header:?} field {:?} should be unique",
                    field.name
                );
            }
        }
    }

    #[test]
    fn packet_protocol_views_are_unique_and_alias_resolved() {
        let mut edges = HashSet::new();
        for header in PacketHeaderKind::all() {
            for view in header.protocol_views() {
                assert_eq!(view.from, *header);
                assert!(
                    edges.insert((view.from, view.to)),
                    "packet protocol view {view:?} should be unique"
                );
                for alias in view.to.aliases() {
                    assert_eq!(
                        view.from.protocol_view_target(alias),
                        Some(view.to),
                        "packet protocol view {view:?} should accept target alias {alias:?}"
                    );
                }
            }
        }
    }
}
