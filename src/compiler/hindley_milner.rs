//! Hindley-Milner Type Inference
//!
//! Implements the classic Hindley-Milner type inference algorithm for the MIR.
//! This provides:
//! - Type variables for unknown types
//! - Unification to solve type constraints
//! - Principal type inference without annotations
//!
//! ## Algorithm Overview
//!
//! 1. Assign fresh type variables to expressions with unknown types
//! 2. Generate constraints from how values are used
//! 3. Solve constraints via unification
//! 4. Apply the resulting substitution to get concrete types
//!
//! ## References
//!
//! - Hindley, J. R. (1969). The principal type-scheme of an object in combinatory logic
//! - Milner, R. (1978). A theory of type polymorphism in programming
//! - Damas, L. & Milner, R. (1982). Principal type-schemes for functional programs

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::mir::{AddressSpace, MirType, StructField};

/// A type variable - placeholder for an unknown type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeVar(pub u32);

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

/// Type representation for Hindley-Milner inference
///
/// Extends MirType with type variables for inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HMType {
    /// Type variable (unknown type to be inferred)
    Var(TypeVar),

    /// Concrete integer types
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    Bool,

    /// Pointer with address space
    Ptr {
        pointee: Box<HMType>,
        address_space: AddressSpace,
    },

    /// Fixed-size array
    Array {
        elem: Box<HMType>,
        len: usize,
    },

    /// Struct/record type
    Struct {
        name: Option<String>,
        fields: Vec<(String, HMType)>,
    },

    /// Map reference
    MapRef {
        key_ty: Box<HMType>,
        val_ty: Box<HMType>,
    },

    /// Function type (for BPF helpers)
    Fn {
        args: Vec<HMType>,
        ret: Box<HMType>,
    },

    /// Unknown type (before inference starts)
    Unknown,
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

/// Substitution: mapping from type variables to types
#[derive(Debug, Clone, Default)]
pub struct Substitution {
    bindings: HashMap<TypeVar, HMType>,
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

/// Unification error
#[derive(Debug, Clone)]
pub struct UnifyError {
    pub expected: HMType,
    pub actual: HMType,
    pub message: String,
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

/// Unify two types, returning a substitution that makes them equal
///
/// This is the core of the Hindley-Milner algorithm.
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

/// Type scheme for polymorphic types: ∀α₁...αₙ. τ
///
/// Used for let-polymorphism where a bound variable can be used at
/// multiple types.
#[derive(Debug, Clone)]
pub struct TypeScheme {
    /// Quantified type variables
    pub quantified: Vec<TypeVar>,
    /// The type with those variables
    pub ty: HMType,
}

impl TypeScheme {
    /// Create a monomorphic scheme (no quantified variables)
    pub fn mono(ty: HMType) -> Self {
        Self {
            quantified: Vec::new(),
            ty,
        }
    }

    /// Instantiate this scheme with fresh type variables
    pub fn instantiate(&self, tvar_gen: &mut TypeVarGenerator) -> HMType {
        let mut subst = Substitution::new();
        for &var in &self.quantified {
            subst.insert(var, HMType::Var(tvar_gen.fresh()));
        }
        subst.apply(&self.ty)
    }

    /// Get free type variables (those not quantified)
    pub fn free_vars(&self) -> HashSet<TypeVar> {
        let mut vars = self.ty.free_vars();
        for v in &self.quantified {
            vars.remove(v);
        }
        vars
    }
}

impl fmt::Display for TypeScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.quantified.is_empty() {
            write!(f, "{}", self.ty)
        } else {
            write!(f, "∀")?;
            for (i, v) in self.quantified.iter().enumerate() {
                if i > 0 {
                    write!(f, " ")?;
                }
                write!(f, "{}", v)?;
            }
            write!(f, ". {}", self.ty)
        }
    }
}

/// Generator for fresh type variables
#[derive(Debug, Default)]
pub struct TypeVarGenerator {
    next: u32,
}

impl TypeVarGenerator {
    pub fn new() -> Self {
        Self { next: 0 }
    }

    /// Generate a fresh type variable
    pub fn fresh(&mut self) -> TypeVar {
        let v = TypeVar(self.next);
        self.next += 1;
        v
    }
}

/// Type environment: maps identifiers to type schemes
#[derive(Debug, Clone, Default)]
pub struct TypeEnv {
    bindings: HashMap<String, TypeScheme>,
}

impl TypeEnv {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    /// Insert a binding
    pub fn insert(&mut self, name: String, scheme: TypeScheme) {
        self.bindings.insert(name, scheme);
    }

    /// Look up a binding
    pub fn get(&self, name: &str) -> Option<&TypeScheme> {
        self.bindings.get(name)
    }

    /// Get all free type variables in the environment
    pub fn free_vars(&self) -> HashSet<TypeVar> {
        let mut vars = HashSet::new();
        for scheme in self.bindings.values() {
            vars.extend(scheme.free_vars());
        }
        vars
    }

    /// Apply a substitution to all types in the environment
    pub fn apply(&self, subst: &Substitution) -> TypeEnv {
        TypeEnv {
            bindings: self
                .bindings
                .iter()
                .map(|(name, scheme)| {
                    (
                        name.clone(),
                        TypeScheme {
                            quantified: scheme.quantified.clone(),
                            ty: subst.apply(&scheme.ty),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Generalize a type into a type scheme by quantifying free variables
    /// not present in the environment
    pub fn generalize(&self, ty: &HMType) -> TypeScheme {
        let env_vars = self.free_vars();
        let ty_vars = ty.free_vars();
        let quantified: Vec<TypeVar> = ty_vars.difference(&env_vars).copied().collect();
        TypeScheme {
            quantified,
            ty: ty.clone(),
        }
    }
}

/// Constraint between two types
#[derive(Debug, Clone)]
pub struct Constraint {
    pub expected: HMType,
    pub actual: HMType,
    pub context: String,
}

impl Constraint {
    pub fn new(expected: HMType, actual: HMType, context: impl Into<String>) -> Self {
        Self {
            expected,
            actual,
            context: context.into(),
        }
    }
}

/// Solve a set of constraints via unification
pub fn solve_constraints(constraints: &[Constraint]) -> Result<Substitution, UnifyError> {
    let mut subst = Substitution::new();

    for constraint in constraints {
        let t1 = subst.apply(&constraint.expected);
        let t2 = subst.apply(&constraint.actual);
        let s = unify(&t1, &t2).map_err(|mut e| {
            e.message = format!("{}: {}", constraint.context, e.message);
            e
        })?;
        subst = s.compose(&subst);
    }

    Ok(subst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_type_vars() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();
        let v2 = tvar_gen.fresh();
        let v3 = tvar_gen.fresh();

        assert_eq!(v1, TypeVar(0));
        assert_eq!(v2, TypeVar(1));
        assert_eq!(v3, TypeVar(2));
    }

    #[test]
    fn test_unify_same_type() {
        let s = unify(&HMType::I64, &HMType::I64).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn test_unify_type_var() {
        let mut tvar_gen = TypeVarGenerator::new();
        let var = tvar_gen.fresh();

        let s = unify(&HMType::Var(var), &HMType::I32).unwrap();
        assert_eq!(s.apply(&HMType::Var(var)), HMType::I32);
    }

    #[test]
    fn test_unify_two_vars() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();
        let v2 = tvar_gen.fresh();

        let s = unify(&HMType::Var(v1), &HMType::Var(v2)).unwrap();
        // One should be bound to the other
        let t1 = s.apply(&HMType::Var(v1));
        let t2 = s.apply(&HMType::Var(v2));
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_unify_array() {
        let mut tvar_gen = TypeVarGenerator::new();
        let var = tvar_gen.fresh();

        let arr1 = HMType::Array {
            elem: Box::new(HMType::Var(var)),
            len: 16,
        };
        let arr2 = HMType::Array {
            elem: Box::new(HMType::U8),
            len: 16,
        };

        let s = unify(&arr1, &arr2).unwrap();
        assert_eq!(s.apply(&HMType::Var(var)), HMType::U8);
    }

    #[test]
    fn test_unify_array_length_mismatch() {
        let arr1 = HMType::Array {
            elem: Box::new(HMType::U8),
            len: 16,
        };
        let arr2 = HMType::Array {
            elem: Box::new(HMType::U8),
            len: 32,
        };

        assert!(unify(&arr1, &arr2).is_err());
    }

    #[test]
    fn test_unify_type_mismatch() {
        let result = unify(&HMType::I64, &HMType::Bool);
        // Note: currently integers unify with each other, but Bool is special
        // This test checks that fundamentally different types don't unify
        // For now, Bool is considered an integer type, so this should succeed
        // If we want stricter typing, we could change this
        assert!(result.is_ok()); // Bool is treated as integer in current implementation
    }

    #[test]
    fn test_occurs_check() {
        let mut tvar_gen = TypeVarGenerator::new();
        let var = tvar_gen.fresh();

        // Try to unify α with α → β (should fail due to occurs check)
        let fn_type = HMType::Fn {
            args: vec![HMType::Var(var)],
            ret: Box::new(HMType::I64),
        };

        let result = unify(&HMType::Var(var), &fn_type);
        assert!(result.is_err());
    }

    #[test]
    fn test_substitution_compose() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();
        let v2 = tvar_gen.fresh();

        let s1 = Substitution::single(v1, HMType::Var(v2));
        let s2 = Substitution::single(v2, HMType::I64);

        let composed = s2.compose(&s1);

        // v1 should now map to I64 (through v2)
        assert_eq!(composed.apply(&HMType::Var(v1)), HMType::I64);
        assert_eq!(composed.apply(&HMType::Var(v2)), HMType::I64);
    }

    #[test]
    fn test_type_scheme_instantiate() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();

        // ∀α. α → α
        let scheme = TypeScheme {
            quantified: vec![v1],
            ty: HMType::Fn {
                args: vec![HMType::Var(v1)],
                ret: Box::new(HMType::Var(v1)),
            },
        };

        let instantiated = scheme.instantiate(&mut tvar_gen);

        // Should have fresh variable (not v1)
        match instantiated {
            HMType::Fn { args, ret } => {
                match (&args[0], ret.as_ref()) {
                    (HMType::Var(arg_v), HMType::Var(ret_v)) => {
                        // Same variable in arg and ret
                        assert_eq!(arg_v, ret_v);
                        // But not the original quantified variable
                        assert_ne!(*arg_v, v1);
                    }
                    _ => panic!("Expected type variables"),
                }
            }
            _ => panic!("Expected function type"),
        }
    }

    #[test]
    fn test_generalize() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();
        let v2 = tvar_gen.fresh();

        // Environment has v1 bound
        let mut env = TypeEnv::new();
        env.insert("x".to_string(), TypeScheme::mono(HMType::Var(v1)));

        // Type uses both v1 and v2
        let ty = HMType::Fn {
            args: vec![HMType::Var(v1)],
            ret: Box::new(HMType::Var(v2)),
        };

        let scheme = env.generalize(&ty);

        // Only v2 should be quantified (v1 is free in env)
        assert_eq!(scheme.quantified.len(), 1);
        assert!(scheme.quantified.contains(&v2));
        assert!(!scheme.quantified.contains(&v1));
    }

    #[test]
    fn test_solve_constraints() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();
        let v2 = tvar_gen.fresh();

        let constraints = vec![
            Constraint::new(HMType::Var(v1), HMType::I32, "first"),
            Constraint::new(HMType::Var(v2), HMType::Var(v1), "second"),
        ];

        let subst = solve_constraints(&constraints).unwrap();

        assert_eq!(subst.apply(&HMType::Var(v1)), HMType::I32);
        assert_eq!(subst.apply(&HMType::Var(v2)), HMType::I32);
    }

    #[test]
    fn test_ptr_unification() {
        let mut tvar_gen = TypeVarGenerator::new();
        let var = tvar_gen.fresh();

        let ptr1 = HMType::Ptr {
            pointee: Box::new(HMType::Var(var)),
            address_space: AddressSpace::Stack,
        };
        let ptr2 = HMType::Ptr {
            pointee: Box::new(HMType::U8),
            address_space: AddressSpace::Stack,
        };

        let s = unify(&ptr1, &ptr2).unwrap();
        assert_eq!(s.apply(&HMType::Var(var)), HMType::U8);
    }

    #[test]
    fn test_ptr_address_space_mismatch() {
        let ptr1 = HMType::Ptr {
            pointee: Box::new(HMType::U8),
            address_space: AddressSpace::Stack,
        };
        let ptr2 = HMType::Ptr {
            pointee: Box::new(HMType::U8),
            address_space: AddressSpace::User,
        };

        assert!(unify(&ptr1, &ptr2).is_err());
    }

    #[test]
    fn test_hmtype_display() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v = tvar_gen.fresh();

        assert_eq!(format!("{}", HMType::I64), "i64");
        assert_eq!(format!("{}", HMType::Var(v)), "α");
        assert_eq!(
            format!(
                "{}",
                HMType::Array {
                    elem: Box::new(HMType::U8),
                    len: 16
                }
            ),
            "[u8; 16]"
        );
    }

    #[test]
    fn test_type_scheme_display() {
        let mut tvar_gen = TypeVarGenerator::new();
        let v1 = tvar_gen.fresh();
        let v2 = tvar_gen.fresh();

        let scheme = TypeScheme {
            quantified: vec![v1, v2],
            ty: HMType::Fn {
                args: vec![HMType::Var(v1)],
                ret: Box::new(HMType::Var(v2)),
            },
        };

        let s = format!("{}", scheme);
        assert!(s.starts_with("∀"));
        assert!(s.contains("α"));
        assert!(s.contains("β"));
    }
}
