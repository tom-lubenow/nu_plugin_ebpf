use super::*;

impl fmt::Display for TypeVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use Greek letters for type variables: α, β, γ, ...
        let greek = ['α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ'];
        if (self.0 as usize) < greek.len() {
            write!(f, "{}", greek[self.0 as usize])
        } else {
            write!(f, "τ{}", self.0)
        }
    }
}

impl HMType {
    /// Check if this type contains a type variable
    pub fn contains_var(&self, var: TypeVar) -> bool {
        match self {
            HMType::Var(v) => *v == var,
            HMType::Ptr { pointee, .. } => pointee.contains_var(var),
            HMType::Array { elem, .. } => elem.contains_var(var),
            HMType::Struct { fields, .. } => fields.iter().any(|(_, ty)| ty.contains_var(var)),
            HMType::MapRef { key_ty, val_ty } => {
                key_ty.contains_var(var) || val_ty.contains_var(var)
            }
            HMType::Fn { args, ret } => {
                args.iter().any(|ty| ty.contains_var(var)) || ret.contains_var(var)
            }
            _ => false,
        }
    }

    /// Get all free type variables in this type
    pub fn free_vars(&self) -> HashSet<TypeVar> {
        let mut vars = HashSet::new();
        self.collect_vars(&mut vars);
        vars
    }

    fn collect_vars(&self, vars: &mut HashSet<TypeVar>) {
        match self {
            HMType::Var(v) => {
                vars.insert(*v);
            }
            HMType::Ptr { pointee, .. } => pointee.collect_vars(vars),
            HMType::Array { elem, .. } => elem.collect_vars(vars),
            HMType::Struct { fields, .. } => {
                for (_, ty) in fields {
                    ty.collect_vars(vars);
                }
            }
            HMType::MapRef { key_ty, val_ty } => {
                key_ty.collect_vars(vars);
                val_ty.collect_vars(vars);
            }
            HMType::Fn { args, ret } => {
                for arg in args {
                    arg.collect_vars(vars);
                }
                ret.collect_vars(vars);
            }
            _ => {}
        }
    }

    /// Check if this is an integer type
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            HMType::I8
                | HMType::I16
                | HMType::I32
                | HMType::I64
                | HMType::U8
                | HMType::U16
                | HMType::U32
                | HMType::U64
                | HMType::Bool
        )
    }

    /// Check if this is a numeric type (integers)
    pub fn is_numeric(&self) -> bool {
        self.is_integer()
    }

    /// Convert to MirType (fails if type variables remain)
    pub fn to_mir_type(&self) -> Option<MirType> {
        match self {
            HMType::Var(_) => None, // Unresolved type variable
            HMType::I8 => Some(MirType::I8),
            HMType::I16 => Some(MirType::I16),
            HMType::I32 => Some(MirType::I32),
            HMType::I64 => Some(MirType::I64),
            HMType::U8 => Some(MirType::U8),
            HMType::U16 => Some(MirType::U16),
            HMType::U32 => Some(MirType::U32),
            HMType::U64 => Some(MirType::U64),
            HMType::Bool => Some(MirType::Bool),
            HMType::Ptr {
                pointee,
                address_space,
            } => Some(MirType::Ptr {
                pointee: Box::new(pointee.to_mir_type()?),
                address_space: *address_space,
            }),
            HMType::Array { elem, len } => Some(MirType::Array {
                elem: Box::new(elem.to_mir_type()?),
                len: *len,
            }),
            HMType::Struct { name, fields } => {
                let mut mir_fields = Vec::new();
                let mut offset = 0;
                for (field_name, ty) in fields {
                    let mir_ty = ty.to_mir_type()?;
                    let size = mir_ty.size();
                    mir_fields.push(StructField {
                        name: field_name.clone(),
                        ty: mir_ty,
                        offset,
                    });
                    offset += size;
                }
                Some(MirType::Struct {
                    name: name.clone(),
                    fields: mir_fields,
                })
            }
            HMType::MapRef { key_ty, val_ty } => Some(MirType::MapRef {
                key_ty: Box::new(key_ty.to_mir_type()?),
                val_ty: Box::new(val_ty.to_mir_type()?),
            }),
            HMType::Fn { .. } => None, // MirType doesn't have function types
            HMType::Unknown => Some(MirType::Unknown),
        }
    }

    /// Convert from MirType
    pub fn from_mir_type(mir: &MirType) -> Self {
        match mir {
            MirType::I8 => HMType::I8,
            MirType::I16 => HMType::I16,
            MirType::I32 => HMType::I32,
            MirType::I64 => HMType::I64,
            MirType::U8 => HMType::U8,
            MirType::U16 => HMType::U16,
            MirType::U32 => HMType::U32,
            MirType::U64 => HMType::U64,
            MirType::Bool => HMType::Bool,
            MirType::Ptr {
                pointee,
                address_space,
            } => HMType::Ptr {
                pointee: Box::new(HMType::from_mir_type(pointee)),
                address_space: *address_space,
            },
            MirType::Array { elem, len } => HMType::Array {
                elem: Box::new(HMType::from_mir_type(elem)),
                len: *len,
            },
            MirType::Struct { name, fields } => HMType::Struct {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|f| (f.name.clone(), HMType::from_mir_type(&f.ty)))
                    .collect(),
            },
            MirType::MapRef { key_ty, val_ty } => HMType::MapRef {
                key_ty: Box::new(HMType::from_mir_type(key_ty)),
                val_ty: Box::new(HMType::from_mir_type(val_ty)),
            },
            MirType::Unknown => HMType::Unknown,
        }
    }
}

impl fmt::Display for HMType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HMType::Var(v) => write!(f, "{}", v),
            HMType::I8 => write!(f, "i8"),
            HMType::I16 => write!(f, "i16"),
            HMType::I32 => write!(f, "i32"),
            HMType::I64 => write!(f, "i64"),
            HMType::U8 => write!(f, "u8"),
            HMType::U16 => write!(f, "u16"),
            HMType::U32 => write!(f, "u32"),
            HMType::U64 => write!(f, "u64"),
            HMType::Bool => write!(f, "bool"),
            HMType::Ptr { pointee, .. } => write!(f, "*{}", pointee),
            HMType::Array { elem, len } => write!(f, "[{}; {}]", elem, len),
            HMType::Struct { name, .. } => {
                if let Some(n) = name {
                    write!(f, "struct {}", n)
                } else {
                    write!(f, "struct")
                }
            }
            HMType::MapRef { key_ty, val_ty } => write!(f, "map<{}, {}>", key_ty, val_ty),
            HMType::Fn { args, ret } => {
                write!(f, "fn(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ") -> {}", ret)
            }
            HMType::Unknown => write!(f, "?"),
        }
    }
}

impl Substitution {
    /// Create an empty substitution
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    /// Create a substitution with a single binding
    pub fn single(var: TypeVar, ty: HMType) -> Self {
        let mut s = Self::new();
        s.bindings.insert(var, ty);
        s
    }

    /// Apply this substitution to a type
    pub fn apply(&self, ty: &HMType) -> HMType {
        match ty {
            HMType::Var(v) => {
                if let Some(bound) = self.bindings.get(v) {
                    // Apply recursively in case bound type contains vars
                    self.apply(bound)
                } else {
                    ty.clone()
                }
            }
            HMType::Ptr {
                pointee,
                address_space,
            } => HMType::Ptr {
                pointee: Box::new(self.apply(pointee)),
                address_space: *address_space,
            },
            HMType::Array { elem, len } => HMType::Array {
                elem: Box::new(self.apply(elem)),
                len: *len,
            },
            HMType::Struct { name, fields } => HMType::Struct {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|(n, ty)| (n.clone(), self.apply(ty)))
                    .collect(),
            },
            HMType::MapRef { key_ty, val_ty } => HMType::MapRef {
                key_ty: Box::new(self.apply(key_ty)),
                val_ty: Box::new(self.apply(val_ty)),
            },
            HMType::Fn { args, ret } => HMType::Fn {
                args: args.iter().map(|ty| self.apply(ty)).collect(),
                ret: Box::new(self.apply(ret)),
            },
            _ => ty.clone(),
        }
    }

    /// Compose two substitutions: self ∘ other
    /// Applying (self ∘ other) is equivalent to applying other then self
    pub fn compose(&self, other: &Substitution) -> Substitution {
        let mut result = Substitution::new();

        // Apply self to all bindings in other
        for (var, ty) in &other.bindings {
            result.bindings.insert(*var, self.apply(ty));
        }

        // Add bindings from self that aren't in other
        for (var, ty) in &self.bindings {
            result.bindings.entry(*var).or_insert_with(|| ty.clone());
        }

        result
    }

    /// Check if this substitution is empty
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Get the binding for a type variable
    pub fn get(&self, var: TypeVar) -> Option<&HMType> {
        self.bindings.get(&var)
    }

    /// Insert a binding
    pub fn insert(&mut self, var: TypeVar, ty: HMType) {
        self.bindings.insert(var, ty);
    }
}

impl UnifyError {
    pub fn new(expected: HMType, actual: HMType, message: impl Into<String>) -> Self {
        Self {
            expected,
            actual,
            message: message.into(),
        }
    }
}

impl fmt::Display for UnifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: expected {}, got {}",
            self.message, self.expected, self.actual
        )
    }
}

impl std::error::Error for UnifyError {}

pub fn unify(t1: &HMType, t2: &HMType) -> Result<Substitution, UnifyError> {
    match (t1, t2) {
        // Same concrete types unify trivially
        (HMType::I8, HMType::I8)
        | (HMType::I16, HMType::I16)
        | (HMType::I32, HMType::I32)
        | (HMType::I64, HMType::I64)
        | (HMType::U8, HMType::U8)
        | (HMType::U16, HMType::U16)
        | (HMType::U32, HMType::U32)
        | (HMType::U64, HMType::U64)
        | (HMType::Bool, HMType::Bool)
        | (HMType::Unknown, HMType::Unknown) => Ok(Substitution::new()),

        // Type variable unification
        (HMType::Var(v), ty) | (ty, HMType::Var(v)) => {
            // Same variable unifies with itself
            if let HMType::Var(v2) = ty
                && v == v2
            {
                return Ok(Substitution::new());
            }
            // Occurs check: prevent infinite types like α = α → β
            if ty.contains_var(*v) {
                return Err(UnifyError::new(
                    t1.clone(),
                    t2.clone(),
                    format!("infinite type: {} occurs in {}", v, ty),
                ));
            }
            Ok(Substitution::single(*v, ty.clone()))
        }

        // Unknown unifies with anything (for backwards compatibility)
        (HMType::Unknown, _) | (_, HMType::Unknown) => {
            // Unknown acts like a wildcard
            Ok(Substitution::new())
        }

        // Integer coercion: allow implicit widening
        (t1, t2) if t1.is_integer() && t2.is_integer() => {
            // For now, just accept all integer combinations
            // Could add size checking for stricter typing
            Ok(Substitution::new())
        }

        // Pointer unification
        (
            HMType::Ptr {
                pointee: p1,
                address_space: a1,
            },
            HMType::Ptr {
                pointee: p2,
                address_space: a2,
            },
        ) => {
            if a1 != a2 {
                return Err(UnifyError::new(
                    t1.clone(),
                    t2.clone(),
                    "pointer address spaces don't match",
                ));
            }
            unify(p1, p2)
        }

        // Array unification
        (HMType::Array { elem: e1, len: l1 }, HMType::Array { elem: e2, len: l2 }) => {
            if l1 != l2 {
                return Err(UnifyError::new(
                    t1.clone(),
                    t2.clone(),
                    format!("array lengths don't match: {} vs {}", l1, l2),
                ));
            }
            unify(e1, e2)
        }

        // Struct unification
        (
            HMType::Struct {
                name: n1,
                fields: f1,
            },
            HMType::Struct {
                name: n2,
                fields: f2,
            },
        ) => {
            if n1 != n2 {
                return Err(UnifyError::new(
                    t1.clone(),
                    t2.clone(),
                    format!("struct names don't match: {:?} vs {:?}", n1, n2),
                ));
            }
            if f1.len() != f2.len() {
                return Err(UnifyError::new(
                    t1.clone(),
                    t2.clone(),
                    "struct field counts don't match",
                ));
            }
            let mut subst = Substitution::new();
            for ((name1, ty1), (name2, ty2)) in f1.iter().zip(f2.iter()) {
                if name1 != name2 {
                    return Err(UnifyError::new(
                        t1.clone(),
                        t2.clone(),
                        format!("struct field names don't match: {} vs {}", name1, name2),
                    ));
                }
                let s = unify(&subst.apply(ty1), &subst.apply(ty2))?;
                subst = s.compose(&subst);
            }
            Ok(subst)
        }

        // Map reference unification
        (
            HMType::MapRef {
                key_ty: k1,
                val_ty: v1,
            },
            HMType::MapRef {
                key_ty: k2,
                val_ty: v2,
            },
        ) => {
            let s1 = unify(k1, k2)?;
            let s2 = unify(&s1.apply(v1), &s1.apply(v2))?;
            Ok(s2.compose(&s1))
        }

        // Function type unification
        (HMType::Fn { args: a1, ret: r1 }, HMType::Fn { args: a2, ret: r2 }) => {
            if a1.len() != a2.len() {
                return Err(UnifyError::new(
                    t1.clone(),
                    t2.clone(),
                    format!(
                        "function argument counts don't match: {} vs {}",
                        a1.len(),
                        a2.len()
                    ),
                ));
            }
            let mut subst = Substitution::new();
            for (arg1, arg2) in a1.iter().zip(a2.iter()) {
                let s = unify(&subst.apply(arg1), &subst.apply(arg2))?;
                subst = s.compose(&subst);
            }
            let s = unify(&subst.apply(r1), &subst.apply(r2))?;
            Ok(s.compose(&subst))
        }

        // Types don't match
        _ => Err(UnifyError::new(t1.clone(), t2.clone(), "types don't match")),
    }
}
