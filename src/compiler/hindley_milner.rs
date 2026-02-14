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

mod core_impl;
mod env_impl;
pub use core_impl::unify;
pub use env_impl::solve_constraints;

/// A type variable - placeholder for an unknown type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeVar(pub u32);

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

/// Substitution: mapping from type variables to types
#[derive(Debug, Clone, Default)]
pub struct Substitution {
    bindings: HashMap<TypeVar, HMType>,
}

/// Unification error
#[derive(Debug, Clone)]
pub struct UnifyError {
    pub expected: HMType,
    pub actual: HMType,
    pub message: String,
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

/// Generator for fresh type variables
#[derive(Debug, Default)]
pub struct TypeVarGenerator {
    next: u32,
}

/// Type environment: maps identifiers to type schemes
#[derive(Debug, Clone, Default)]
pub struct TypeEnv {
    bindings: HashMap<String, TypeScheme>,
}

/// Constraint between two types
#[derive(Debug, Clone)]
pub struct Constraint {
    pub expected: HMType,
    pub actual: HMType,
    pub context: String,
}

#[cfg(test)]
mod tests;
