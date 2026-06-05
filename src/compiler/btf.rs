//! BTF (BPF Type Format) generation
//!
//! BTF is a metadata format that describes types used in BPF programs.
//! It's required by modern loaders (libbpf, Aya) for map definitions.
//!
//! References:
//! - https://docs.kernel.org/bpf/btf.html
//! - https://docs.ebpf.io/concepts/btf/

/// BTF magic number (little-endian)
const BTF_MAGIC: u16 = 0xEB9F;

/// BTF version
const BTF_VERSION: u8 = 1;

/// BTF type kinds (complete list per BTF specification)
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum BtfKind {
    Unknown = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

/// BTF variable linkage (complete list per BTF specification)
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
#[allow(dead_code)]
pub enum BtfVarLinkage {
    Static = 0,
    GlobalAlloc = 1,
    GlobalExtern = 2,
}

/// BTF type builder
pub struct BtfBuilder {
    /// String section (null-terminated strings)
    strings: Vec<u8>,
    /// Type section (encoded btf_type structs)
    types: Vec<u8>,
    /// Next type ID (starts at 1, 0 is void)
    next_type_id: u32,
    /// First encoding error observed while building BTF.
    error: Option<String>,
}

impl BtfBuilder {
    pub fn new() -> Self {
        let mut builder = Self {
            strings: Vec::new(),
            types: Vec::new(),
            next_type_id: 1,
            error: None,
        };
        // First byte of string section must be null (for empty strings)
        builder.strings.push(0);
        builder
    }

    fn record_error(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }

    fn alloc_type_id(&mut self, what: &str) -> u32 {
        let type_id = self.next_type_id;
        match self.next_type_id.checked_add(1) {
            Some(next_type_id) => self.next_type_id = next_type_id,
            None => self.record_error(format!("BTF type id overflow while adding {what}")),
        }
        type_id
    }

    fn checked_u32_from_usize(&mut self, value: usize, what: &str) -> u32 {
        match u32::try_from(value) {
            Ok(value) => value,
            Err(_) => {
                self.record_error(format!("{what} {value} exceeds BTF u32 encoding limit"));
                0
            }
        }
    }

    fn encode_info_for_len(
        &mut self,
        kind: BtfKind,
        vlen: usize,
        kind_flag: bool,
        what: &str,
    ) -> u32 {
        let vlen = match u16::try_from(vlen) {
            Ok(vlen) => vlen,
            Err(_) => {
                self.record_error(format!(
                    "{what} count {vlen} exceeds BTF vlen encoding limit"
                ));
                0
            }
        };
        Self::encode_info(kind, vlen, kind_flag)
    }

    fn byte_offset_to_bits(&mut self, offset_bytes: u32, what: &str) -> u32 {
        match offset_bytes.checked_mul(8) {
            Some(offset_bits) => offset_bits,
            None => {
                self.record_error(format!(
                    "{what} byte offset {offset_bytes} exceeds BTF bit-offset encoding limit"
                ));
                0
            }
        }
    }

    fn pointer_member_offset_bits(&mut self, index: usize, what: &str) -> u32 {
        match index.checked_mul(64) {
            Some(offset_bits) => self.checked_u32_from_usize(offset_bits, what),
            None => {
                self.record_error(format!("{what} index {index} exceeds BTF bit-offset range"));
                0
            }
        }
    }

    /// Add a string to the string section, return its offset
    fn add_string(&mut self, s: &str) -> u32 {
        let offset = self.checked_u32_from_usize(self.strings.len(), "BTF string offset");
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0); // null terminator
        offset
    }

    /// Encode the info field: vlen (bits 0-15), kind (bits 24-28), kind_flag (bit 31)
    fn encode_info(kind: BtfKind, vlen: u16, kind_flag: bool) -> u32 {
        let mut info = vlen as u32;
        info |= (kind as u32) << 24;
        if kind_flag {
            info |= 1 << 31;
        }
        info
    }

    /// Add an integer type, return its type ID
    pub fn add_int(&mut self, name: &str, size: u32, is_signed: bool) -> u32 {
        let name_off = self.add_string(name);
        let type_id = self.alloc_type_id("integer type");

        // btf_type header
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::Int, 0, false).to_le_bytes());
        self.types.extend_from_slice(&size.to_le_bytes()); // size in bytes

        // BTF_INT encoding: bits 0-7 = nr_bits, bits 16-23 = offset, bits 24-27 = encoding
        // See: https://docs.kernel.org/bpf/btf.html
        let nr_bits = match size.checked_mul(8).filter(|bits| *bits <= u8::MAX as u32) {
            Some(bits) => bits,
            None => {
                self.record_error(format!(
                    "integer type {name:?} size {size} exceeds BTF int bit-width encoding limit"
                ));
                0
            }
        };
        let encoding = if is_signed { 1u32 } else { 0u32 };
        let int_data = nr_bits | (encoding << 24);
        self.types.extend_from_slice(&int_data.to_le_bytes());

        type_id
    }

    /// Add a pointer type, return its type ID
    pub fn add_ptr(&mut self, target_type_id: u32) -> u32 {
        let type_id = self.alloc_type_id("pointer type");

        // btf_type header (name_off = 0 for pointers)
        self.types.extend_from_slice(&0u32.to_le_bytes()); // name_off
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::Ptr, 0, false).to_le_bytes());
        self.types.extend_from_slice(&target_type_id.to_le_bytes()); // type

        type_id
    }

    /// Add a forward declaration type, return its type ID.
    pub fn add_fwd(&mut self, name: &str, is_union: bool) -> u32 {
        let name_off = self.add_string(name);
        let type_id = self.alloc_type_id("forward declaration");

        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::Fwd, 0, is_union).to_le_bytes());
        self.types.extend_from_slice(&0u32.to_le_bytes());

        type_id
    }

    /// Add a type tag, return its type ID.
    pub fn add_type_tag(&mut self, tag: &str, target_type_id: u32) -> u32 {
        let name_off = self.add_string(tag);
        let type_id = self.alloc_type_id("type tag");

        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::TypeTag, 0, false).to_le_bytes());
        self.types.extend_from_slice(&target_type_id.to_le_bytes());

        type_id
    }

    /// Add a declaration tag, return its type ID.
    ///
    /// `component_idx` is `-1` for a tag attached to the target declaration
    /// itself, or a zero-based struct/union member index for field tags.
    #[allow(dead_code)]
    pub fn add_decl_tag(&mut self, tag: &str, target_type_id: u32, component_idx: i32) -> u32 {
        let name_off = self.add_string(tag);
        let type_id = self.alloc_type_id("declaration tag");

        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::DeclTag, 0, false).to_le_bytes());
        self.types.extend_from_slice(&target_type_id.to_le_bytes());
        self.types.extend_from_slice(&component_idx.to_le_bytes());

        type_id
    }

    /// Add an array type, return its type ID
    ///
    /// Arrays in BTF have an element type, index type (usually u32), and number of elements.
    pub fn add_array(&mut self, elem_type: u32, index_type: u32, nelems: u32) -> u32 {
        let type_id = self.alloc_type_id("array type");

        // btf_type header (name_off = 0 for arrays, size = 0)
        self.types.extend_from_slice(&0u32.to_le_bytes()); // name_off
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::Array, 0, false).to_le_bytes());
        self.types.extend_from_slice(&0u32.to_le_bytes()); // size (unused for arrays)

        // btf_array data
        self.types.extend_from_slice(&elem_type.to_le_bytes());
        self.types.extend_from_slice(&index_type.to_le_bytes());
        self.types.extend_from_slice(&nelems.to_le_bytes());

        type_id
    }

    /// Create a __uint(name, val) type pattern: PTR -> ARRAY[val] -> INT
    ///
    /// This matches the libbpf macro: #define __uint(name, val) int (*name)[val]
    /// Used for BTF-defined map attributes like type, key_size, value_size, etc.
    pub fn add_uint_type(&mut self, int_type: u32, value: u32) -> u32 {
        // Create ARRAY[value] of int
        let array_type = self.add_array(int_type, int_type, value);
        // Create PTR to the array
        self.add_ptr(array_type)
    }

    /// Add a struct type, return its type ID
    ///
    /// Members are: (name, type_id, size_in_bytes)
    #[allow(dead_code)]
    pub fn add_struct(&mut self, name: &str, members: &[(&str, u32, u32)]) -> u32 {
        let name_off = self.add_string(name);
        let type_id = self.alloc_type_id("struct type");

        // Calculate total size from members
        let mut size = 0u32;
        for (_, _, member_size) in members {
            match size.checked_add(*member_size) {
                Some(next_size) => size = next_size,
                None => {
                    self.record_error(format!(
                        "struct {name:?} size exceeds BTF u32 encoding limit"
                    ));
                    break;
                }
            }
        }

        // btf_type header
        self.types.extend_from_slice(&name_off.to_le_bytes());
        let info = self.encode_info_for_len(BtfKind::Struct, members.len(), false, "struct member");
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size.to_le_bytes());

        // Member entries
        let mut offset = 0u32;
        for (member_name, member_type, member_size) in members {
            let member_name_off = self.add_string(member_name);
            self.types.extend_from_slice(&member_name_off.to_le_bytes());
            self.types.extend_from_slice(&member_type.to_le_bytes());
            let offset_bits = self.byte_offset_to_bits(offset, "struct member");
            self.types.extend_from_slice(&offset_bits.to_le_bytes());
            match offset.checked_add(*member_size) {
                Some(next_offset) => offset = next_offset,
                None => self.record_error(format!(
                    "struct {name:?} member offsets exceed BTF u32 encoding limit"
                )),
            }
        }

        type_id
    }

    /// Add a struct type with explicit member offsets (in bytes), return its type ID.
    pub fn add_struct_with_offsets(
        &mut self,
        name: &str,
        size: u32,
        members: &[(&str, u32, u32)],
    ) -> u32 {
        let name_off = self.add_string(name);
        let type_id = self.alloc_type_id("struct type");

        self.types.extend_from_slice(&name_off.to_le_bytes());
        let info = self.encode_info_for_len(BtfKind::Struct, members.len(), false, "struct member");
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size.to_le_bytes());

        for (member_name, member_type, member_offset_bytes) in members {
            let member_name_off = self.add_string(member_name);
            self.types.extend_from_slice(&member_name_off.to_le_bytes());
            self.types.extend_from_slice(&member_type.to_le_bytes());
            let offset_bits = self.byte_offset_to_bits(*member_offset_bytes, "struct member");
            self.types.extend_from_slice(&offset_bits.to_le_bytes());
        }

        type_id
    }

    /// Add an anonymous struct (no name) with pointer-sized members
    ///
    /// This is used for BTF-defined maps where all fields are pointers.
    /// Members are: (name, type_id) - all members are pointer-sized (8 bytes)
    pub fn add_btf_map_struct(&mut self, members: &[(&str, u32)]) -> u32 {
        let type_id = self.alloc_type_id("BTF map struct");

        // Size = number of members * 8 (pointer size)
        let size = match members.len().checked_mul(8) {
            Some(size) => self.checked_u32_from_usize(size, "BTF map struct size"),
            None => {
                self.record_error(format!(
                    "BTF map struct member count {} exceeds size encoding limit",
                    members.len()
                ));
                0
            }
        };

        // btf_type header (name_off = 0 for anonymous struct)
        self.types.extend_from_slice(&0u32.to_le_bytes()); // name_off = 0 (anonymous)
        let info = self.encode_info_for_len(BtfKind::Struct, members.len(), false, "map member");
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size.to_le_bytes());

        // Member entries (each pointer is 8 bytes)
        for (idx, (member_name, member_type)) in members.iter().enumerate() {
            let member_name_off = self.add_string(member_name);
            self.types.extend_from_slice(&member_name_off.to_le_bytes());
            self.types.extend_from_slice(&member_type.to_le_bytes());
            let offset_bits = self.pointer_member_offset_bits(idx, "map member");
            self.types.extend_from_slice(&offset_bits.to_le_bytes());
        }

        type_id
    }

    /// Add an anonymous BTF-defined map struct with an explicit byte size.
    ///
    /// This is used for map-in-map/prog-array definitions whose final `values`
    /// member is a zero-sized flexible array. The member is present in BTF at
    /// the end of the fixed fields, but it does not contribute to struct size.
    pub fn add_btf_map_struct_with_size(&mut self, members: &[(&str, u32)], size: u32) -> u32 {
        let type_id = self.alloc_type_id("BTF map struct");

        self.types.extend_from_slice(&0u32.to_le_bytes());
        let info = self.encode_info_for_len(BtfKind::Struct, members.len(), false, "map member");
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size.to_le_bytes());

        for (idx, (member_name, member_type)) in members.iter().enumerate() {
            let member_name_off = self.add_string(member_name);
            self.types.extend_from_slice(&member_name_off.to_le_bytes());
            self.types.extend_from_slice(&member_type.to_le_bytes());
            let offset_bits = self.pointer_member_offset_bits(idx, "map member");
            self.types.extend_from_slice(&offset_bits.to_le_bytes());
        }

        type_id
    }

    /// Add a variable, return its type ID
    pub fn add_var(&mut self, name: &str, type_id: u32, linkage: BtfVarLinkage) -> u32 {
        let name_off = self.add_string(name);
        let var_type_id = self.alloc_type_id("variable");

        // btf_type header
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types
            .extend_from_slice(&Self::encode_info(BtfKind::Var, 0, false).to_le_bytes());
        self.types.extend_from_slice(&type_id.to_le_bytes());

        // btf_var
        self.types
            .extend_from_slice(&(linkage as u32).to_le_bytes());

        var_type_id
    }

    /// Add a function prototype type, return its type ID.
    ///
    /// Params are `(name, type_id)` pairs.
    pub fn add_func_proto(&mut self, return_type: u32, params: &[(&str, u32)]) -> u32 {
        let type_id = self.alloc_type_id("function prototype");

        self.types.extend_from_slice(&0u32.to_le_bytes()); // name_off = 0
        let info = self.encode_info_for_len(
            BtfKind::FuncProto,
            params.len(),
            false,
            "function parameter",
        );
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&return_type.to_le_bytes());

        for (param_name, param_type) in params {
            let param_name_off = self.add_string(param_name);
            self.types.extend_from_slice(&param_name_off.to_le_bytes());
            self.types.extend_from_slice(&param_type.to_le_bytes());
        }

        type_id
    }

    /// Add a datasec (describes a section like .maps), return its type ID
    pub fn add_datasec(&mut self, name: &str, vars: &[(u32, u32, u32)]) -> u32 {
        let name_off = self.add_string(name);
        let type_id = self.alloc_type_id("data section");

        // Calculate total size
        let mut size = 0u32;
        for (_, _, var_size) in vars {
            match size.checked_add(*var_size) {
                Some(next_size) => size = next_size,
                None => {
                    self.record_error(format!(
                        "data section {name:?} size exceeds BTF u32 encoding limit"
                    ));
                    break;
                }
            }
        }

        // btf_type header
        self.types.extend_from_slice(&name_off.to_le_bytes());
        let info = self.encode_info_for_len(BtfKind::DataSec, vars.len(), false, "data section");
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size.to_le_bytes());

        // btf_var_secinfo entries
        for (var_type_id, offset, size) in vars {
            self.types.extend_from_slice(&var_type_id.to_le_bytes());
            self.types.extend_from_slice(&offset.to_le_bytes());
            self.types.extend_from_slice(&size.to_le_bytes());
        }

        type_id
    }

    /// Build the complete BTF blob
    pub fn try_build(mut self) -> Result<Vec<u8>, String> {
        let hdr_len = 24u32; // Size of btf_header
        let type_off = 0u32;
        let type_len = self.checked_u32_from_usize(self.types.len(), "BTF type section length");
        let str_off = type_len;
        let str_len = self.checked_u32_from_usize(self.strings.len(), "BTF string section length");

        if let Some(error) = self.error {
            return Err(error);
        }

        let mut btf = Vec::with_capacity(hdr_len as usize + type_len as usize + str_len as usize);

        // Header
        btf.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        btf.push(BTF_VERSION);
        btf.push(0); // flags
        btf.extend_from_slice(&hdr_len.to_le_bytes());
        btf.extend_from_slice(&type_off.to_le_bytes());
        btf.extend_from_slice(&type_len.to_le_bytes());
        btf.extend_from_slice(&str_off.to_le_bytes());
        btf.extend_from_slice(&str_len.to_le_bytes());

        // Type section
        btf.extend_from_slice(&self.types);

        // String section
        btf.extend_from_slice(&self.strings);

        Ok(btf)
    }

    /// Build the complete BTF blob, panicking if it contains unencodable metadata.
    pub fn build(self) -> Vec<u8> {
        self.try_build().expect("invalid BTF metadata")
    }
}

/// Generate BTF for a perf event array map
#[allow(dead_code)]
pub fn generate_perf_map_btf(map_name: &str) -> Vec<u8> {
    let mut btf = BtfBuilder::new();

    // Add basic types
    let u32_type = btf.add_int("__u32", 4, false);

    // For a perf event array, we define a struct with the map attributes
    // This matches what libbpf/Aya expects for BTF-defined maps
    let map_struct = btf.add_struct(
        map_name,
        &[
            ("type", u32_type, 4),
            ("key_size", u32_type, 4),
            ("value_size", u32_type, 4),
            ("max_entries", u32_type, 4),
        ],
    );

    // Add a variable for the map
    let map_var = btf.add_var(map_name, map_struct, BtfVarLinkage::GlobalAlloc);

    // Add datasec for .maps section
    btf.add_datasec(".maps", &[(map_var, 0, 16)]);

    btf.build()
}

#[cfg(test)]
mod tests;
