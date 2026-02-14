use super::*;

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

impl Constraint {
    pub fn new(expected: HMType, actual: HMType, context: impl Into<String>) -> Self {
        Self {
            expected,
            actual,
            context: context.into(),
        }
    }
}

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
