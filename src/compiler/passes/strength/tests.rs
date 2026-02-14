
use super::*;
use crate::compiler::mir::MirValue;

#[test]
fn test_mul_by_power_of_two() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x * 8 -> x << 3
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Mul,
        lhs: lhs.clone(),
        rhs: MirValue::Const(8),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::BinOp {
            op: BinOpKind::Shl,
            rhs: MirValue::Const(3),
            ..
        } => {}
        _ => panic!("Expected shift left by 3, got {:?}", reduced),
    }
}

#[test]
fn test_div_by_power_of_two() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x / 16 -> x >> 4
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Div,
        lhs: lhs.clone(),
        rhs: MirValue::Const(16),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::BinOp {
            op: BinOpKind::Shr,
            rhs: MirValue::Const(4),
            ..
        } => {}
        _ => panic!("Expected shift right by 4, got {:?}", reduced),
    }
}

#[test]
fn test_mod_by_power_of_two() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x % 8 -> x & 7
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Mod,
        lhs: lhs.clone(),
        rhs: MirValue::Const(8),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::BinOp {
            op: BinOpKind::And,
            rhs: MirValue::Const(7),
            ..
        } => {}
        _ => panic!("Expected AND with 7, got {:?}", reduced),
    }
}

#[test]
fn test_mul_by_zero() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x * 0 -> 0
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Mul,
        lhs: lhs.clone(),
        rhs: MirValue::Const(0),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        } => {}
        _ => panic!("Expected copy of 0, got {:?}", reduced),
    }
}

#[test]
fn test_mul_by_one() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x * 1 -> x
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Mul,
        lhs: lhs.clone(),
        rhs: MirValue::Const(1),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy { src, .. } => assert_eq!(src, lhs),
        _ => panic!("Expected copy of lhs, got {:?}", reduced),
    }
}

#[test]
fn test_add_zero() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x + 0 -> x
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Add,
        lhs: lhs.clone(),
        rhs: MirValue::Const(0),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy { src, .. } => assert_eq!(src, lhs),
        _ => panic!("Expected copy of lhs, got {:?}", reduced),
    }
}

#[test]
fn test_no_reduction_for_non_power_of_two() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

    // x * 7 -> no change
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Mul,
        lhs: lhs.clone(),
        rhs: MirValue::Const(7),
    };

    assert!(sr.reduce(&inst).is_none());
}

// Algebraic identity tests

#[test]
fn test_x_sub_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x - x -> 0
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        } => {}
        _ => panic!("Expected x - x = 0, got {:?}", reduced),
    }
}

#[test]
fn test_x_xor_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x ^ x -> 0
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Xor,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        } => {}
        _ => panic!("Expected x ^ x = 0, got {:?}", reduced),
    }
}

#[test]
fn test_x_or_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x | x -> x
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Or,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::VReg(v),
            ..
        } => assert_eq!(v, x, "Expected x | x = x"),
        _ => panic!("Expected x | x = x, got {:?}", reduced),
    }
}

#[test]
fn test_x_and_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x & x -> x
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::And,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::VReg(v),
            ..
        } => assert_eq!(v, x, "Expected x & x = x"),
        _ => panic!("Expected x & x = x, got {:?}", reduced),
    }
}

#[test]
fn test_x_eq_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x == x -> 1
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(1),
            ..
        } => {}
        _ => panic!("Expected x == x = 1, got {:?}", reduced),
    }
}

#[test]
fn test_x_ne_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x != x -> 0
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        } => {}
        _ => panic!("Expected x != x = 0, got {:?}", reduced),
    }
}

#[test]
fn test_x_le_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x <= x -> 1
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(1),
            ..
        } => {}
        _ => panic!("Expected x <= x = 1, got {:?}", reduced),
    }
}

#[test]
fn test_x_lt_x() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);

    // x < x -> 0
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Lt,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(x),
    };

    let reduced = sr.reduce(&inst).unwrap();
    match reduced {
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        } => {}
        _ => panic!("Expected x < x = 0, got {:?}", reduced),
    }
}

#[test]
fn test_different_vregs_no_reduction() {
    let sr = StrengthReduction;
    let dst = crate::compiler::mir::VReg(0);
    let x = crate::compiler::mir::VReg(1);
    let y = crate::compiler::mir::VReg(2);

    // x - y -> no change (different vregs)
    let inst = MirInst::BinOp {
        dst,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(x),
        rhs: MirValue::VReg(y),
    };

    assert!(
        sr.reduce(&inst).is_none(),
        "Different vregs should not reduce"
    );
}
