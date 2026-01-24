//! Type representations for kernel BTF information

/// Information about a type from kernel BTF
#[derive(Debug, Clone)]
pub enum TypeInfo {
    /// Integer type
    Int {
        /// Size in bytes
        size: usize,
        /// Whether the integer is signed
        signed: bool,
    },
    /// Pointer to another type
    Ptr {
        /// The target type
        target: Box<TypeInfo>,
        /// Whether this is a __user pointer
        is_user: bool,
    },
    /// Struct type
    Struct {
        /// Struct name
        name: String,
        /// Size in bytes
        size: usize,
    },
    /// Array type
    Array {
        /// Element type
        element: Box<TypeInfo>,
        /// Number of elements
        len: usize,
    },
    /// Void type
    Void,
    /// Unknown or unsupported type
    Unknown,
}

impl TypeInfo {
    /// Get the size of this type in bytes
    pub fn size(&self) -> usize {
        match self {
            TypeInfo::Int { size, .. } => *size,
            TypeInfo::Ptr { .. } => 8, // 64-bit pointers
            TypeInfo::Struct { size, .. } => *size,
            TypeInfo::Array { element, len } => element.size() * len,
            TypeInfo::Void => 0,
            TypeInfo::Unknown => 8, // Assume pointer-sized
        }
    }

    /// Check if this is an integer type
    pub fn is_int(&self) -> bool {
        matches!(self, TypeInfo::Int { .. })
    }

    /// Check if this is a pointer type
    pub fn is_ptr(&self) -> bool {
        matches!(self, TypeInfo::Ptr { .. })
    }
}

/// Information about a struct field
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name
    pub name: String,
    /// Field type
    pub type_info: TypeInfo,
    /// Offset in bytes from start of struct
    pub offset: usize,
    /// Size in bytes
    pub size: usize,
}
