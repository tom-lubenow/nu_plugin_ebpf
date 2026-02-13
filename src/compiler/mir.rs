//! Mid-Level Intermediate Representation (MIR) for eBPF compilation
//!
//! MIR sits between Nushell IR and eBPF bytecode, providing:
//! - Virtual registers (unlimited, unlike eBPF's 10)
//! - Explicit basic blocks with terminators
//! - Type information for verification
//! - A target for optimization passes

use std::collections::HashMap;
use std::fmt;

/// Virtual register ID - unlimited, will be allocated to physical registers later
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VReg(pub u32);

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Basic block identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Stack slot identifier for explicit stack allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackSlotId(pub u32);

/// Subfunction identifier for BPF-to-BPF calls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubfunctionId(pub u32);

impl fmt::Display for SubfunctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "subfn{}", self.0)
    }
}

/// Map reference for BPF map operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MapRef {
    pub name: String,
    pub kind: MapKind,
}

/// Types of BPF maps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapKind {
    Hash,
    Array,
    PerCpuHash,
    PerCpuArray,
    RingBuf,
    StackTrace,
    ProgArray,
}

pub const RINGBUF_MAP_NAME: &str = "events";
pub const COUNTER_MAP_NAME: &str = "counters";
pub const STRING_COUNTER_MAP_NAME: &str = "str_counters";
pub const HISTOGRAM_MAP_NAME: &str = "histogram";
pub const TIMESTAMP_MAP_NAME: &str = "timestamps";
pub const KSTACK_MAP_NAME: &str = "kstacks";
pub const USTACK_MAP_NAME: &str = "ustacks";

/// Type of value being appended in StringAppend
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringAppendType {
    /// Append a literal string (bytes embedded in MIR)
    Literal { bytes: Vec<u8> },
    /// Append from a string slot on the stack
    StringSlot { slot: StackSlotId, max_len: usize },
    /// Append an integer converted to decimal
    Integer,
}

/// MIR type system - internal, inferred from context
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirType {
    // Primitives
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    Bool,

    // Pointers with address space (for verifier)
    Ptr {
        pointee: Box<MirType>,
        address_space: AddressSpace,
    },

    // Fixed-size array
    Array {
        elem: Box<MirType>,
        len: usize,
    },

    // Struct with named fields
    Struct {
        name: Option<String>,
        fields: Vec<StructField>,
    },

    // BPF-specific
    MapRef {
        key_ty: Box<MirType>,
        val_ty: Box<MirType>,
    },

    // Unknown type (before inference)
    Unknown,
}

impl MirType {
    /// Size in bytes
    pub fn size(&self) -> usize {
        match self {
            MirType::I8 | MirType::U8 | MirType::Bool => 1,
            MirType::I16 | MirType::U16 => 2,
            MirType::I32 | MirType::U32 => 4,
            MirType::I64 | MirType::U64 => 8,
            MirType::Ptr { .. } => 8,
            MirType::Array { elem, len } => elem.size() * len,
            MirType::Struct { fields, .. } => fields.iter().map(|f| f.ty.size()).sum(),
            MirType::MapRef { .. } => 8, // Map FD
            MirType::Unknown => 8,       // Default to 64-bit
        }
    }

    /// Alignment in bytes
    pub fn align(&self) -> usize {
        match self {
            MirType::I8 | MirType::U8 | MirType::Bool => 1,
            MirType::I16 | MirType::U16 => 2,
            MirType::I32 | MirType::U32 => 4,
            MirType::I64 | MirType::U64 | MirType::Ptr { .. } => 8,
            MirType::Array { elem, .. } => elem.align(),
            MirType::Struct { fields, .. } => {
                fields.iter().map(|f| f.ty.align()).max().unwrap_or(1)
            }
            MirType::MapRef { .. } => 8,
            MirType::Unknown => 8,
        }
    }
}

/// Address space for pointer provenance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressSpace {
    /// Stack-relative (R10 + offset), always valid
    Stack,
    /// Kernel memory, requires bpf_probe_read_kernel
    Kernel,
    /// User memory, requires bpf_probe_read_user
    User,
    /// Map value pointer (trusted after null check)
    Map,
}

/// Field in a struct type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    pub name: String,
    pub ty: MirType,
    pub offset: usize,
}

/// A field in a record being emitted
#[derive(Debug, Clone)]
pub struct RecordFieldDef {
    /// Field name
    pub name: String,
    /// Virtual register holding the value
    pub value: VReg,
    /// Type of the field
    pub ty: MirType,
}

/// Stack slot for explicit stack allocation
#[derive(Debug, Clone)]
pub struct StackSlot {
    pub id: StackSlotId,
    pub size: usize,
    pub align: usize,
    pub kind: StackSlotKind,
    /// Assigned offset from R10 (negative), filled in during layout
    pub offset: Option<i16>,
}

/// Purpose of a stack slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackSlotKind {
    /// Register spill
    Spill,
    /// Local variable
    Local,
    /// Outgoing call argument
    Argument,
    /// Event buffer for ring buffer output
    EventBuffer,
    /// String comparison buffer
    StringBuffer,
    /// Record field storage
    RecordField,
    /// List buffer storage (length + elements)
    ListBuffer,
}

/// Value that can be used as an operand
#[derive(Debug, Clone, PartialEq)]
pub enum MirValue {
    /// Virtual register
    VReg(VReg),
    /// Compile-time constant
    Const(i64),
    /// Stack slot reference
    StackSlot(StackSlotId),
}

impl fmt::Display for MirValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirValue::VReg(v) => write!(f, "{}", v),
            MirValue::Const(c) => write!(f, "{}", c),
            MirValue::StackSlot(s) => write!(f, "slot{}", s.0),
        }
    }
}

impl MirValue {
    /// Visit virtual registers referenced by this value.
    pub fn visit_vregs_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut VReg),
    {
        if let MirValue::VReg(vreg) = self {
            f(vreg);
        }
    }

    /// Return a copy of this value with all referenced virtual registers rewritten.
    pub fn map_vregs<F>(&self, mut map: F) -> MirValue
    where
        F: FnMut(VReg) -> VReg,
    {
        let mut cloned = self.clone();
        cloned.visit_vregs_mut(|vreg| *vreg = map(*vreg));
        cloned
    }
}

/// Binary operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Bitwise
    And,
    Or,
    Xor,
    Shl,
    Shr,

    // Comparison (result is 0 or 1)
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOpKind::Add => "+",
            BinOpKind::Sub => "-",
            BinOpKind::Mul => "*",
            BinOpKind::Div => "/",
            BinOpKind::Mod => "%",
            BinOpKind::And => "&",
            BinOpKind::Or => "|",
            BinOpKind::Xor => "^",
            BinOpKind::Shl => "<<",
            BinOpKind::Shr => ">>",
            BinOpKind::Eq => "==",
            BinOpKind::Ne => "!=",
            BinOpKind::Lt => "<",
            BinOpKind::Le => "<=",
            BinOpKind::Gt => ">",
            BinOpKind::Ge => ">=",
        };
        write!(f, "{}", s)
    }
}

/// Unary operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOpKind {
    /// Logical not (0 -> 1, non-zero -> 0)
    Not,
    /// Bitwise negation
    BitNot,
    /// Arithmetic negation
    Neg,
}

/// Context field access
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtxField {
    /// Process ID
    Pid,
    /// Thread ID
    Tid,
    /// User ID
    Uid,
    /// Group ID
    Gid,
    /// Process name (comm)
    Comm,
    /// CPU ID
    Cpu,
    /// Timestamp (nanoseconds)
    Timestamp,
    /// Function argument (kprobe/uprobe)
    Arg(u8),
    /// Return value (kretprobe/uretprobe)
    RetVal,
    /// Kernel stack ID
    KStack,
    /// User stack ID
    UStack,
    /// Tracepoint field by name
    TracepointField(String),
}

/// MIR instruction
#[derive(Debug, Clone)]
pub enum MirInst {
    // Data movement
    /// Copy value to virtual register
    Copy { dst: VReg, src: MirValue },

    /// Load from memory (stack or via pointer)
    Load {
        dst: VReg,
        ptr: VReg,
        offset: i32,
        ty: MirType,
    },

    /// Store to memory
    Store {
        ptr: VReg,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    /// Load from stack slot
    LoadSlot {
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        ty: MirType,
    },

    /// Store to stack slot
    StoreSlot {
        slot: StackSlotId,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    // Arithmetic
    /// Binary operation
    BinOp {
        dst: VReg,
        op: BinOpKind,
        lhs: MirValue,
        rhs: MirValue,
    },

    /// Unary operation
    UnaryOp {
        dst: VReg,
        op: UnaryOpKind,
        src: MirValue,
    },

    // BPF helpers
    /// Call BPF helper function
    CallHelper {
        dst: VReg,
        helper: u32, // BPF helper ID
        args: Vec<MirValue>,
    },

    /// Call BPF kfunc (BTF-described kernel function)
    CallKfunc {
        dst: VReg,
        kfunc: String,
        /// Optional explicit BTF ID. If absent, backend resolves from `kfunc`.
        btf_id: Option<u32>,
        args: Vec<VReg>,
    },

    /// Map lookup
    MapLookup { dst: VReg, map: MapRef, key: VReg },

    /// Map update
    MapUpdate {
        map: MapRef,
        key: VReg,
        val: VReg,
        flags: u64,
    },

    /// Map delete
    MapDelete { map: MapRef, key: VReg },

    /// Histogram aggregation - computes log2 bucket and increments counter
    Histogram {
        /// Value to compute histogram bucket for
        value: VReg,
    },

    /// Start timer - stores current ktime keyed by TID
    StartTimer,

    /// Stop timer - looks up start time, computes delta, deletes entry
    /// Result is stored in dst (0 if no matching start)
    StopTimer { dst: VReg },

    /// Emit event to ring buffer
    EmitEvent { data: VReg, size: usize },

    /// Emit structured record to ring buffer
    EmitRecord {
        /// Fields to emit, in order
        fields: Vec<RecordFieldDef>,
    },

    // Context access
    /// Load context field
    LoadCtxField {
        dst: VReg,
        field: CtxField,
        /// Optional stack slot backing the field (for stack-based ctx data like comm)
        slot: Option<StackSlotId>,
    },

    // String operations
    /// Read string from user/kernel memory
    ReadStr {
        dst: StackSlotId,
        ptr: VReg,
        user_space: bool,
        max_len: usize,
    },

    /// Compare two strings on stack
    StrCmp {
        dst: VReg,
        lhs: StackSlotId,
        rhs: StackSlotId,
        len: usize,
    },

    /// Append a value to a string buffer
    /// dst_buffer is the destination string buffer on stack
    /// dst_len is a vreg holding the current string length
    /// val is the value to append (string slot or int)
    StringAppend {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: MirValue,
        val_type: StringAppendType,
    },

    /// Format an integer as decimal string into a buffer
    /// Used for string interpolation with integers
    IntToString {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: VReg,
    },

    // Record building
    /// Store field to record buffer
    RecordStore {
        buffer: StackSlotId,
        field_offset: usize,
        val: MirValue,
        ty: MirType,
    },

    // List operations
    /// Initialize an empty list on the stack
    /// Layout: [length: u64, elem0: u64, elem1: u64, ...]
    /// max_len determines the allocated buffer size
    ListNew {
        dst: VReg,
        buffer: StackSlotId,
        max_len: usize,
    },

    /// Push an element onto the end of a list
    /// Stores at offset (length * 8) + 8, then increments length
    ListPush { list: VReg, item: VReg },

    /// Get the current length of a list
    ListLen { dst: VReg, list: VReg },

    /// Get an element from a list by index
    /// Returns 0 if index out of bounds
    ListGet {
        dst: VReg,
        list: VReg,
        idx: MirValue,
    },

    // SSA phi function
    /// Phi node for SSA form - selects value based on incoming edge
    /// Must appear at the start of a block, before any non-phi instructions
    Phi {
        dst: VReg,
        /// (predecessor block, value from that predecessor)
        args: Vec<(BlockId, VReg)>,
    },

    // Control flow (terminators - must be last in block)
    /// Unconditional jump
    Jump { target: BlockId },

    /// Conditional branch
    Branch {
        cond: VReg,
        if_true: BlockId,
        if_false: BlockId,
    },

    /// Return from program
    Return { val: Option<MirValue> },

    /// Tail call to another program
    TailCall { prog_map: MapRef, index: MirValue },

    /// Call a BPF subfunction (BPF-to-BPF call)
    /// Arguments are passed in R1-R5, return value in R0
    CallSubfn {
        dst: VReg,
        subfn: SubfunctionId,
        args: Vec<VReg>,
    },

    // Pseudo-instructions (expanded during lowering)
    /// Bounded loop header (eBPF verifier requirement)
    LoopHeader {
        counter: VReg,
        limit: i64,
        body: BlockId,
        exit: BlockId,
    },

    /// Loop increment and back-edge
    LoopBack {
        counter: VReg,
        step: i64,
        header: BlockId,
    },

    /// Placeholder terminator (not a real terminator, must be replaced)
    Placeholder,
}

impl MirInst {
    /// Returns true if this instruction is a terminator
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            MirInst::Jump { .. }
                | MirInst::Branch { .. }
                | MirInst::Return { .. }
                | MirInst::TailCall { .. }
        )
    }

    /// Visit all virtual registers used as operands by this instruction.
    ///
    /// This walks use sites only (not destination definitions) so passes can
    /// safely rewrite operands in-place.
    pub fn visit_uses_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut VReg),
    {
        macro_rules! visit_value {
            ($value:expr) => {
                if let MirValue::VReg(vreg) = $value {
                    f(vreg);
                }
            };
        }

        match self {
            MirInst::Copy { src, .. } => visit_value!(src),
            MirInst::Load { ptr, .. } => f(ptr),
            MirInst::Store { ptr, val, .. } => {
                f(ptr);
                visit_value!(val);
            }
            MirInst::LoadSlot { .. } => {}
            MirInst::StoreSlot { val, .. } => visit_value!(val),
            MirInst::BinOp { lhs, rhs, .. } => {
                visit_value!(lhs);
                visit_value!(rhs);
            }
            MirInst::UnaryOp { src, .. } => visit_value!(src),
            MirInst::CallHelper { args, .. } => {
                for arg in args {
                    visit_value!(arg);
                }
            }
            MirInst::CallKfunc { args, .. } | MirInst::CallSubfn { args, .. } => {
                for arg in args {
                    f(arg);
                }
            }
            MirInst::MapLookup { key, .. } => f(key),
            MirInst::MapUpdate { key, val, .. } => {
                f(key);
                f(val);
            }
            MirInst::MapDelete { key, .. } => f(key),
            MirInst::Histogram { value, .. } => f(value),
            MirInst::StartTimer => {}
            MirInst::StopTimer { .. } => {}
            MirInst::EmitEvent { data, .. } => f(data),
            MirInst::EmitRecord { fields } => {
                for field in fields {
                    f(&mut field.value);
                }
            }
            MirInst::LoadCtxField { .. } => {}
            MirInst::ReadStr { ptr, .. } => f(ptr),
            MirInst::StrCmp { .. } => {}
            MirInst::RecordStore { val, .. } => visit_value!(val),
            MirInst::ListNew { .. } => {}
            MirInst::ListPush { list, item } => {
                f(list);
                f(item);
            }
            MirInst::ListLen { list, .. } => f(list),
            MirInst::ListGet { list, idx, .. } => {
                f(list);
                visit_value!(idx);
            }
            MirInst::Jump { .. } => {}
            MirInst::Branch { cond, .. } => f(cond),
            MirInst::Return { val } => {
                if let Some(value) = val {
                    visit_value!(value);
                }
            }
            MirInst::TailCall { index, .. } => visit_value!(index),
            MirInst::LoopHeader { .. } => {}
            MirInst::LoopBack { counter, .. } => f(counter),
            MirInst::Placeholder => {}
            MirInst::Phi { args, .. } => {
                for (_, vreg) in args {
                    f(vreg);
                }
            }
            MirInst::StringAppend { dst_len, val, .. } => {
                f(dst_len);
                visit_value!(val);
            }
            MirInst::IntToString { dst_len, val, .. } => {
                f(dst_len);
                f(val);
            }
        }
    }

    /// Return a copy of this instruction with all operand vregs rewritten.
    pub fn map_uses<F>(&self, mut map: F) -> MirInst
    where
        F: FnMut(VReg) -> VReg,
    {
        let mut cloned = self.clone();
        cloned.visit_uses_mut(|vreg| *vreg = map(*vreg));
        cloned
    }

    /// Returns the destination register if this instruction writes to one
    pub fn def(&self) -> Option<VReg> {
        match self {
            MirInst::Copy { dst, .. }
            | MirInst::Load { dst, .. }
            | MirInst::LoadSlot { dst, .. }
            | MirInst::BinOp { dst, .. }
            | MirInst::UnaryOp { dst, .. }
            | MirInst::CallHelper { dst, .. }
            | MirInst::CallKfunc { dst, .. }
            | MirInst::CallSubfn { dst, .. }
            | MirInst::MapLookup { dst, .. }
            | MirInst::LoadCtxField { dst, .. }
            | MirInst::StrCmp { dst, .. }
            | MirInst::StopTimer { dst, .. }
            | MirInst::LoopHeader { counter: dst, .. }
            | MirInst::ListNew { dst, .. }
            | MirInst::ListLen { dst, .. }
            | MirInst::ListGet { dst, .. }
            | MirInst::Phi { dst, .. } => Some(*dst),
            _ => None,
        }
    }

    /// Returns virtual registers used by this instruction
    pub fn uses(&self) -> Vec<VReg> {
        let mut uses = Vec::new();
        let add_value = |uses: &mut Vec<VReg>, v: &MirValue| {
            if let MirValue::VReg(r) = v {
                uses.push(*r);
            }
        };

        match self {
            MirInst::Copy { src, .. } => add_value(&mut uses, src),
            MirInst::Load { ptr, .. } => uses.push(*ptr),
            MirInst::Store { ptr, val, .. } => {
                uses.push(*ptr);
                add_value(&mut uses, val);
            }
            MirInst::LoadSlot { .. } => {}
            MirInst::StoreSlot { val, .. } => add_value(&mut uses, val),
            MirInst::BinOp { lhs, rhs, .. } => {
                add_value(&mut uses, lhs);
                add_value(&mut uses, rhs);
            }
            MirInst::UnaryOp { src, .. } => add_value(&mut uses, src),
            MirInst::CallHelper { args, .. } => {
                for arg in args {
                    add_value(&mut uses, arg);
                }
            }
            MirInst::CallKfunc { args, .. } => {
                for arg in args {
                    uses.push(*arg);
                }
            }
            MirInst::CallSubfn { args, .. } => {
                for arg in args {
                    uses.push(*arg);
                }
            }
            MirInst::MapLookup { key, .. } => uses.push(*key),
            MirInst::MapUpdate { key, val, .. } => {
                uses.push(*key);
                uses.push(*val);
            }
            MirInst::MapDelete { key, .. } => uses.push(*key),
            MirInst::Histogram { value, .. } => uses.push(*value),
            MirInst::StartTimer => {}
            MirInst::StopTimer { .. } => {}
            MirInst::EmitEvent { data, .. } => uses.push(*data),
            MirInst::EmitRecord { fields } => {
                for field in fields {
                    uses.push(field.value);
                }
            }
            MirInst::LoadCtxField { .. } => {}
            MirInst::ReadStr { ptr, .. } => uses.push(*ptr),
            MirInst::StrCmp { .. } => {}
            MirInst::RecordStore { val, .. } => add_value(&mut uses, val),
            MirInst::ListNew { .. } => {}
            MirInst::ListPush { list, item } => {
                uses.push(*list);
                uses.push(*item);
            }
            MirInst::ListLen { list, .. } => uses.push(*list),
            MirInst::ListGet { list, idx, .. } => {
                uses.push(*list);
                add_value(&mut uses, idx);
            }
            MirInst::Jump { .. } => {}
            MirInst::Branch { cond, .. } => uses.push(*cond),
            MirInst::Return { val } => {
                if let Some(v) = val {
                    add_value(&mut uses, v);
                }
            }
            MirInst::TailCall { index, .. } => add_value(&mut uses, index),
            MirInst::LoopHeader { counter, .. } => uses.push(*counter),
            MirInst::LoopBack { counter, .. } => uses.push(*counter),
            MirInst::Placeholder => {} // No uses
            MirInst::Phi { args, .. } => {
                for (_, vreg) in args {
                    uses.push(*vreg);
                }
            }
            MirInst::StringAppend { dst_len, val, .. } => {
                uses.push(*dst_len);
                add_value(&mut uses, val);
            }
            MirInst::IntToString { dst_len, val, .. } => {
                uses.push(*dst_len);
                uses.push(*val);
            }
        }
        uses
    }
}

/// A basic block with instructions and a terminator
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Non-terminator instructions
    pub instructions: Vec<MirInst>,
    /// Block terminator (must be Jump, Branch, Return, or TailCall)
    pub terminator: MirInst,
}

impl BasicBlock {
    /// Create a new basic block
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            terminator: MirInst::Placeholder, // Must be replaced with a real terminator
        }
    }

    /// Get successor block IDs
    pub fn successors(&self) -> Vec<BlockId> {
        match &self.terminator {
            MirInst::Jump { target } => vec![*target],
            MirInst::Branch {
                if_true, if_false, ..
            } => vec![*if_true, *if_false],
            MirInst::LoopHeader { body, exit, .. } => vec![*body, *exit],
            MirInst::LoopBack { header, .. } => vec![*header],
            MirInst::Return { .. } | MirInst::TailCall { .. } => vec![],
            MirInst::Placeholder => vec![], // Placeholder has no successors yet
            _ => panic!("Invalid terminator: {:?}", self.terminator),
        }
    }
}

/// A complete MIR function
#[derive(Debug, Clone)]
pub struct MirFunction {
    /// Function name (for debugging and ELF section naming)
    pub name: Option<String>,
    /// Basic blocks (entry block is first)
    pub blocks: Vec<BasicBlock>,
    /// Entry block ID
    pub entry: BlockId,
    /// Number of virtual registers used
    pub vreg_count: u32,
    /// Stack slots
    pub stack_slots: Vec<StackSlot>,
    /// Maps used by this function
    pub maps_used: Vec<MapRef>,
    /// Parameter count (for BPF subfunction calling convention)
    pub param_count: usize,
}

impl MirFunction {
    /// Create a new empty MIR function
    pub fn new() -> Self {
        Self {
            name: None,
            blocks: Vec::new(),
            entry: BlockId(0),
            vreg_count: 0,
            stack_slots: Vec::new(),
            maps_used: Vec::new(),
            param_count: 0,
        }
    }

    /// Create a new named MIR function (for subfunctions)
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new()
        }
    }

    /// Allocate a new virtual register
    pub fn alloc_vreg(&mut self) -> VReg {
        let vreg = VReg(self.vreg_count);
        self.vreg_count += 1;
        vreg
    }

    /// Allocate a new stack slot
    pub fn alloc_stack_slot(
        &mut self,
        size: usize,
        align: usize,
        kind: StackSlotKind,
    ) -> StackSlotId {
        let id = StackSlotId(self.stack_slots.len() as u32);
        self.stack_slots.push(StackSlot {
            id,
            size,
            align,
            kind,
            offset: None,
        });
        id
    }

    /// Allocate a new basic block
    pub fn alloc_block(&mut self) -> BlockId {
        let id = BlockId(self.blocks.len() as u32);
        self.blocks.push(BasicBlock::new(id));
        id
    }

    /// Get a mutable reference to a block
    pub fn block_mut(&mut self, id: BlockId) -> &mut BasicBlock {
        let idx = id.0 as usize;
        let fast_path = self.blocks.get(idx).is_some_and(|b| b.id == id);
        if fast_path {
            return &mut self.blocks[idx];
        }
        self.blocks
            .iter_mut()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("Block {:?} not found", id))
    }

    /// Get a reference to a block
    pub fn block(&self, id: BlockId) -> &BasicBlock {
        let idx = id.0 as usize;
        if let Some(block) = self.blocks.get(idx)
            && block.id == id
        {
            return block;
        }
        self.blocks
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("Block {:?} not found", id))
    }

    /// Check if a block exists
    pub fn has_block(&self, id: BlockId) -> bool {
        let idx = id.0 as usize;
        if self.blocks.get(idx).is_some_and(|b| b.id == id) {
            return true;
        }
        self.blocks.iter().any(|b| b.id == id)
    }
}

impl Default for MirFunction {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete MIR program (may have subfunctions for BPF-to-BPF calls)
#[derive(Debug, Clone)]
pub struct MirProgram {
    /// Main function
    pub main: MirFunction,
    /// Subfunctions (for BPF-to-BPF calls)
    pub subfunctions: Vec<MirFunction>,
}

/// Optional type hints for MIR registers, usually derived from HIR inference.
#[derive(Debug, Clone, Default)]
pub struct MirTypeHints {
    pub main: HashMap<VReg, MirType>,
    pub subfunctions: Vec<HashMap<VReg, MirType>>,
}

impl MirProgram {
    pub fn new(main: MirFunction) -> Self {
        Self {
            main,
            subfunctions: Vec::new(),
        }
    }

    /// Add a subfunction and return its ID
    pub fn add_subfunction(&mut self, func: MirFunction) -> SubfunctionId {
        let id = SubfunctionId(self.subfunctions.len() as u32);
        self.subfunctions.push(func);
        id
    }

    /// Get a subfunction by ID
    pub fn get_subfunction(&self, id: SubfunctionId) -> Option<&MirFunction> {
        self.subfunctions.get(id.0 as usize)
    }

    /// Get a mutable reference to a subfunction by ID
    pub fn get_subfunction_mut(&mut self, id: SubfunctionId) -> Option<&mut MirFunction> {
        self.subfunctions.get_mut(id.0 as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_lookup_index_fast_path_and_fallback() {
        let mut func = MirFunction::new();
        let b0 = func.alloc_block();
        let b1 = func.alloc_block();

        assert_eq!(func.block(b1).id, b1);

        // Simulate non-index-stable ordering after block rewrites/removals.
        func.blocks.remove(0);

        assert!(!func.has_block(b0));
        assert!(func.has_block(b1));
        assert_eq!(func.block(b1).id, b1);
        func.block_mut(b1).terminator = MirInst::Return { val: None };
        assert!(matches!(func.block(b1).terminator, MirInst::Return { .. }));
    }
}
