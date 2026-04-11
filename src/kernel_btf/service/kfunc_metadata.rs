use std::collections::{HashMap, HashSet};

use btf::Btf;
use btf::btf::Type;

use super::raw_btf::infer_kfunc_ret_shape;
use super::{
    BtfError, KernelBtf, KfuncArgShape, KfuncPointerRefFamily, KfuncRetShape, KfuncSignatureHint,
};

impl KernelBtf {
    pub(super) fn load_kfunc_nullable_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut nullable_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.name.as_deref().is_some_and(|param_name| {
                    param_name.ends_with("__nullable") || param_name.ends_with("__opt")
                }) {
                    nullable_args.push(arg_idx);
                }
            }
            if !nullable_args.is_empty() {
                map.insert(name.clone(), nullable_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_user_pointer_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut user_pointer_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs > 0 && Self::has_user_type_tag(&param_ty.type_tags) {
                    user_pointer_args.push(arg_idx);
                }
            }
            if !user_pointer_args.is_empty() {
                map.insert(name.clone(), user_pointer_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_const_pointer_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut const_pointer_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs > 0 && param_ty.is_const {
                    const_pointer_args.push(arg_idx);
                }
            }
            if !const_pointer_args.is_empty() {
                map.insert(name.clone(), const_pointer_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_stack_pointer_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut stack_pointer_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                let Some(type_name) = param_ty.name.as_deref() else {
                    continue;
                };
                if Self::is_stack_object_type_name(type_name) {
                    stack_pointer_args.push(arg_idx);
                }
            }
            if !stack_pointer_args.is_empty() {
                map.insert(name.clone(), stack_pointer_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_kernel_pointer_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut kernel_pointer_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                let Some(type_name) = param_ty.name.as_deref() else {
                    continue;
                };
                if Self::is_kernel_pointer_type_name(type_name) {
                    kernel_pointer_args.push(arg_idx);
                }
            }
            if !kernel_pointer_args.is_empty() {
                map.insert(name.clone(), kernel_pointer_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_pointer_ref_family_map(
        &self,
    ) -> Result<HashMap<String, Vec<(usize, KfuncPointerRefFamily)>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<(usize, KfuncPointerRefFamily)>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut ref_family_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                let Some(type_name) = param_ty.name.as_deref() else {
                    continue;
                };
                let Some(ref_family) = Self::infer_pointer_ref_family(type_name) else {
                    continue;
                };
                ref_family_args.push((arg_idx, ref_family));
            }
            if !ref_family_args.is_empty() {
                map.insert(name.clone(), ref_family_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_return_ref_family_map(
        &self,
    ) -> Result<HashMap<String, KfuncPointerRefFamily>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let mut map: HashMap<String, KfuncPointerRefFamily> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Some(ret_type_id) = function_ret_type_ids.get(&ty.type_id).copied() else {
                continue;
            };
            let Ok(ret_ty) = btf.get_type_by_id(ret_type_id) else {
                continue;
            };
            if ret_ty.num_refs == 0 || Self::has_user_type_tag(&ret_ty.type_tags) {
                continue;
            }
            let Some(type_name) = ret_ty.name.as_deref() else {
                continue;
            };
            let Some(ref_family) = Self::infer_pointer_ref_family(type_name) else {
                continue;
            };
            map.insert(name.clone(), ref_family);
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_release_ref_arg_index_map(
        &self,
    ) -> Result<HashMap<String, usize>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, usize> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            if !Self::is_probable_release_kfunc_name(name) {
                continue;
            }
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut family_args: Vec<(usize, bool, bool)> = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                let Some(type_name) = param_ty.name.as_deref() else {
                    continue;
                };
                if Self::infer_pointer_ref_family(type_name).is_some() {
                    let is_named_out = param
                        .name
                        .as_deref()
                        .is_some_and(Self::is_probable_out_param_name);
                    family_args.push((arg_idx, is_named_out, param_ty.is_const));
                }
            }
            if let Some(arg_idx) = Self::infer_release_arg_index_from_family_args(&family_args) {
                map.insert(name.clone(), arg_idx);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_signature_hint_map(
        &self,
    ) -> Result<HashMap<String, KfuncSignatureHint>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let function_ret_type_ids = self.load_kfunc_return_type_id_map().unwrap_or_default();
        let mut map: HashMap<String, KfuncSignatureHint> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            if proto.params.len() > 5 {
                continue;
            }
            // BTF varargs are represented by a terminal unnamed param with type_id=0.
            if proto
                .params
                .last()
                .is_some_and(|p| p.type_id == 0 && p.name.is_none())
            {
                continue;
            }
            let mut arg_shapes = [KfuncArgShape::Scalar; 5];
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                if btf
                    .get_type_by_id(param.type_id)
                    .is_ok_and(|param_ty| param_ty.num_refs > 0)
                {
                    arg_shapes[arg_idx] = KfuncArgShape::Pointer;
                }
            }
            let ret_shape = function_ret_type_ids
                .get(&ty.type_id)
                .copied()
                .map(|ret_type_id| infer_kfunc_ret_shape(&btf, ret_type_id))
                .unwrap_or(KfuncRetShape::Scalar);
            map.insert(
                name.clone(),
                KfuncSignatureHint {
                    min_args: proto.params.len(),
                    max_args: proto.params.len(),
                    arg_shapes,
                    ret_shape,
                },
            );
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_known_const_scalar_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut known_const_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.name.as_deref().is_some_and(|param_name| {
                    param_name.ends_with("__szk") || param_name.ends_with("__k")
                }) {
                    known_const_args.push(arg_idx);
                }
            }
            if !known_const_args.is_empty() {
                map.insert(name.clone(), known_const_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_positive_scalar_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };
            let mut positive_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.name.as_deref().is_some_and(|param_name| {
                    param_name.ends_with("__sz") || param_name.ends_with("__szk")
                }) {
                    positive_args.push(arg_idx);
                }
            }
            if !positive_args.is_empty() {
                map.insert(name.clone(), positive_args);
            }
        }
        Ok(map)
    }

    pub(super) fn kfunc_size_param_base_name(param_name: &str) -> Option<&str> {
        let base = param_name
            .strip_suffix("__szk")
            .or_else(|| param_name.strip_suffix("__sz"))?;
        if base.is_empty() {
            return None;
        }
        Some(base)
    }

    pub(super) fn load_kfunc_pointer_size_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<(usize, usize)>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut pointer_args_by_name: HashMap<String, usize> = HashMap::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                if param.type_id == 0 {
                    continue;
                }
                let is_pointer = btf
                    .get_type_by_id(param.type_id)
                    .is_ok_and(|param_ty| param_ty.num_refs > 0);
                if is_pointer {
                    pointer_args_by_name
                        .entry(param_name.to_string())
                        .or_insert(arg_idx);
                }
            }

            let mut ptr_size_pairs: Vec<(usize, usize)> = Vec::new();
            for (size_arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                let Some(base) = Self::kfunc_size_param_base_name(param_name) else {
                    continue;
                };
                let Some(ptr_arg_idx) = pointer_args_by_name.get(base).copied() else {
                    continue;
                };
                if !ptr_size_pairs
                    .iter()
                    .any(|(ptr, size)| *ptr == ptr_arg_idx && *size == size_arg_idx)
                {
                    ptr_size_pairs.push((ptr_arg_idx, size_arg_idx));
                }
            }

            if !ptr_size_pairs.is_empty() {
                map.insert(name.clone(), ptr_size_pairs);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_stack_slot_base_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut pointer_args_by_name: HashMap<String, usize> = HashMap::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                if param.type_id == 0 {
                    continue;
                }
                let is_pointer = btf
                    .get_type_by_id(param.type_id)
                    .is_ok_and(|param_ty| param_ty.num_refs > 0);
                if is_pointer {
                    pointer_args_by_name
                        .entry(param_name.to_string())
                        .or_insert(arg_idx);
                }
            }

            let mut pointer_args_with_dynamic_sizes: HashSet<usize> = HashSet::new();
            for param in &proto.params {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                let Some(base) = Self::kfunc_size_param_base_name(param_name) else {
                    continue;
                };
                if let Some(ptr_arg_idx) = pointer_args_by_name.get(base).copied() {
                    pointer_args_with_dynamic_sizes.insert(ptr_arg_idx);
                }
            }

            let mut stack_slot_base_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if pointer_args_with_dynamic_sizes.contains(&arg_idx) {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs != 1 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                if matches!(param_ty.base_type, Type::Struct(_) | Type::Union(_)) {
                    stack_slot_base_args.push(arg_idx);
                }
            }

            if !stack_slot_base_args.is_empty() {
                map.insert(name.clone(), stack_slot_base_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_out_pointer_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut out_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                if !Self::is_probable_out_param_name(param_name) || param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                out_args.push(arg_idx);
            }

            if !out_args.is_empty() {
                map.insert(name.clone(), out_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_in_pointer_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<usize>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<usize>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut in_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                if !Self::is_probable_in_param_name(param_name) || param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                in_args.push(arg_idx);
            }

            if !in_args.is_empty() {
                map.insert(name.clone(), in_args);
            }
        }
        Ok(map)
    }

    pub(super) fn load_kfunc_stack_object_arg_map(
        &self,
    ) -> Result<HashMap<String, Vec<(usize, u32, String)>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<(usize, u32, String)>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut stack_object_args = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if param.type_id == 0 {
                    continue;
                }
                let Ok(param_ty) = btf.get_type_by_id(param.type_id) else {
                    continue;
                };
                if param_ty.num_refs == 0 || Self::has_user_type_tag(&param_ty.type_tags) {
                    continue;
                }
                let Some(type_name) = param_ty.name.as_deref() else {
                    continue;
                };
                if !Self::is_stack_object_type_name(type_name) {
                    continue;
                }
                stack_object_args.push((arg_idx, param_ty.type_id, type_name.to_string()));
            }
            if !stack_object_args.is_empty() {
                map.insert(name.clone(), stack_object_args);
            }
        }
        Ok(map)
    }

    fn pointer_pointee_size_bytes(btf: &Btf, param_type_id: u32) -> Option<usize> {
        let param_ty = btf.get_type_by_id(param_type_id).ok()?;
        if param_ty.num_refs == 0 {
            return None;
        }
        if param_ty.num_refs > 1 {
            return Some(8);
        }
        let bits = Self::flattened_base_type_bits(btf, &param_ty.base_type)?;
        if bits == 0 {
            return None;
        }
        usize::try_from(bits.div_ceil(8)).ok()
    }

    fn load_kfunc_pointer_fixed_size_map(
        &self,
    ) -> Result<HashMap<String, Vec<(usize, usize)>>, BtfError> {
        let btf = self.load_kernel_btf_for_query()?;
        let mut map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        for ty in btf.get_types() {
            if !ty.is_function || !Self::is_bpf_kfunc(ty) {
                continue;
            }
            let Some(name) = ty.name.as_ref() else {
                continue;
            };
            let Type::FunctionProto(proto) = &ty.base_type else {
                continue;
            };

            let mut pointer_args_by_name: HashMap<String, usize> = HashMap::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                if param.type_id == 0 {
                    continue;
                }
                let is_pointer = btf
                    .get_type_by_id(param.type_id)
                    .is_ok_and(|param_ty| param_ty.num_refs > 0);
                if is_pointer {
                    pointer_args_by_name
                        .entry(param_name.to_string())
                        .or_insert(arg_idx);
                }
            }

            let mut pointer_args_with_dynamic_sizes: HashSet<usize> = HashSet::new();
            for param in &proto.params {
                let Some(param_name) = param.name.as_deref() else {
                    continue;
                };
                let Some(base) = Self::kfunc_size_param_base_name(param_name) else {
                    continue;
                };
                if let Some(ptr_arg_idx) = pointer_args_by_name.get(base).copied() {
                    pointer_args_with_dynamic_sizes.insert(ptr_arg_idx);
                }
            }

            let mut fixed_size_args: Vec<(usize, usize)> = Vec::new();
            for (arg_idx, param) in proto.params.iter().enumerate() {
                if pointer_args_with_dynamic_sizes.contains(&arg_idx) {
                    continue;
                }
                let Some(size_bytes) = Self::pointer_pointee_size_bytes(&btf, param.type_id) else {
                    continue;
                };
                if size_bytes == 0 {
                    continue;
                }
                fixed_size_args.push((arg_idx, size_bytes));
            }

            if !fixed_size_args.is_empty() {
                map.insert(name.clone(), fixed_size_args);
            }
        }
        Ok(map)
    }

    /// Returns whether `kfunc_name` argument `arg_idx` is nullable in local kernel BTF.
    pub fn kfunc_pointer_arg_is_nullable(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_nullable_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|nullable_args| nullable_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_nullable_arg_map().unwrap_or_default();
        let is_nullable = map
            .get(kfunc_name)
            .is_some_and(|nullable_args| nullable_args.contains(&arg_idx));

        let mut cache = self.kfunc_nullable_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_nullable
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` is const-qualified.
    pub fn kfunc_pointer_arg_is_const(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_const_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|const_args| const_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_const_pointer_arg_map().unwrap_or_default();
        let is_const = map
            .get(kfunc_name)
            .is_some_and(|const_args| const_args.contains(&arg_idx));

        let mut cache = self.kfunc_const_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_const
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` requires user-space pointers.
    pub fn kfunc_pointer_arg_requires_user(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_user_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|user_args| user_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_user_pointer_arg_map().unwrap_or_default();
        let requires_user = map
            .get(kfunc_name)
            .is_some_and(|user_args| user_args.contains(&arg_idx));

        let mut cache = self.kfunc_user_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_user
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` requires stack pointers.
    pub fn kfunc_pointer_arg_requires_stack(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_stack_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|stack_args| stack_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_stack_pointer_arg_map().unwrap_or_default();
        let requires_stack = map
            .get(kfunc_name)
            .is_some_and(|stack_args| stack_args.contains(&arg_idx));

        let mut cache = self.kfunc_stack_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_stack
    }

    /// Returns whether `kfunc_name` pointer argument `arg_idx` requires kernel-space pointers.
    pub fn kfunc_pointer_arg_requires_kernel(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_kernel_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|kernel_args| kernel_args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_kernel_pointer_arg_map().unwrap_or_default();
        let requires_kernel = map
            .get(kfunc_name)
            .is_some_and(|kernel_args| kernel_args.contains(&arg_idx));

        let mut cache = self.kfunc_kernel_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_kernel
    }

    /// Returns inferred pointer ref-family metadata for `kfunc_name` argument `arg_idx`.
    pub fn kfunc_pointer_arg_ref_family(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> Option<KfuncPointerRefFamily> {
        {
            let cache = self.kfunc_pointer_ref_family_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|pairs| pairs.iter().find(|(idx, _)| *idx == arg_idx))
                    .map(|(_, family)| *family);
            }
        }

        let map = self.load_kfunc_pointer_ref_family_map().unwrap_or_default();
        let ref_family = map
            .get(kfunc_name)
            .and_then(|pairs| pairs.iter().find(|(idx, _)| *idx == arg_idx))
            .map(|(_, family)| *family);

        let mut cache = self.kfunc_pointer_ref_family_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        ref_family
    }

    /// Returns inferred return-value ref-family metadata for `kfunc_name`.
    pub fn kfunc_return_ref_family(&self, kfunc_name: &str) -> Option<KfuncPointerRefFamily> {
        {
            let cache = self.kfunc_return_ref_family_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.get(kfunc_name).copied();
            }
        }

        let map = self.load_kfunc_return_ref_family_map().unwrap_or_default();
        let ref_family = map.get(kfunc_name).copied();

        let mut cache = self.kfunc_return_ref_family_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        ref_family
    }

    /// Returns inferred release-argument index for `kfunc_name` if unambiguous in local BTF.
    pub fn kfunc_release_ref_arg_index(&self, kfunc_name: &str) -> Option<usize> {
        {
            let cache = self.kfunc_release_ref_arg_index_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.get(kfunc_name).copied();
            }
        }

        let map = self
            .load_kfunc_release_ref_arg_index_map()
            .unwrap_or_default();
        let arg_idx = map.get(kfunc_name).copied();

        let mut cache = self.kfunc_release_ref_arg_index_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        arg_idx
    }

    /// Returns a best-effort coarse kfunc signature inferred from local kernel BTF.
    pub fn kfunc_signature_hint(&self, kfunc_name: &str) -> Option<KfuncSignatureHint> {
        {
            let cache = self.kfunc_signature_hint_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map.get(kfunc_name).copied();
            }
        }

        let map = self.load_kfunc_signature_hint_map().unwrap_or_default();
        let hint = map.get(kfunc_name).copied();

        let mut cache = self.kfunc_signature_hint_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        hint
    }

    /// Returns whether `kfunc_name` scalar argument `arg_idx` must be known constant.
    ///
    /// This is inferred from kernel BTF parameter-name conventions `*__szk` / `*__k`.
    pub fn kfunc_scalar_arg_requires_known_const(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_known_const_scalar_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|known_const_args| known_const_args.contains(&arg_idx));
            }
        }

        let map = self
            .load_kfunc_known_const_scalar_arg_map()
            .unwrap_or_default();
        let is_known_const = map
            .get(kfunc_name)
            .is_some_and(|known_const_args| known_const_args.contains(&arg_idx));

        let mut cache = self.kfunc_known_const_scalar_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_known_const
    }

    /// Returns whether `kfunc_name` scalar argument `arg_idx` must be positive.
    ///
    /// This is inferred from kernel BTF parameter-name conventions `*__sz` / `*__szk`.
    pub fn kfunc_scalar_arg_requires_positive(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_positive_scalar_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|positive_args| positive_args.contains(&arg_idx));
            }
        }

        let map = self
            .load_kfunc_positive_scalar_arg_map()
            .unwrap_or_default();
        let is_positive = map
            .get(kfunc_name)
            .is_some_and(|positive_args| positive_args.contains(&arg_idx));

        let mut cache = self.kfunc_positive_scalar_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_positive
    }

    /// Returns the scalar size-argument index paired with a pointer argument, if available.
    ///
    /// This is inferred from kernel BTF parameter-name conventions `arg` + `arg__sz`/`arg__szk`.
    pub fn kfunc_pointer_arg_size_arg(&self, kfunc_name: &str, arg_idx: usize) -> Option<usize> {
        {
            let cache = self.kfunc_pointer_size_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
                    .map(|(_, size)| *size);
            }
        }

        let map = self.load_kfunc_pointer_size_arg_map().unwrap_or_default();
        let size_arg = map
            .get(kfunc_name)
            .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
            .map(|(_, size)| *size);

        let mut cache = self.kfunc_pointer_size_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        size_arg
    }

    /// Returns the inferred fixed access size for a pointer argument, if available.
    ///
    /// This is inferred from the local kernel BTF pointee type when no
    /// name-paired dynamic `*__sz`/`*__szk` argument exists.
    pub fn kfunc_pointer_arg_fixed_size(&self, kfunc_name: &str, arg_idx: usize) -> Option<usize> {
        {
            let cache = self.kfunc_pointer_fixed_size_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
                    .map(|(_, size)| *size);
            }
        }

        let map = self.load_kfunc_pointer_fixed_size_map().unwrap_or_default();
        let size = map
            .get(kfunc_name)
            .and_then(|pairs| pairs.iter().find(|(ptr, _)| *ptr == arg_idx))
            .map(|(_, size)| *size);

        let mut cache = self.kfunc_pointer_fixed_size_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        size
    }

    /// Returns whether `kfunc_name` pointer arg should be a stack-slot base when in stack space.
    pub fn kfunc_pointer_arg_requires_stack_slot_base(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> bool {
        {
            let cache = self.kfunc_stack_slot_base_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|args| args.contains(&arg_idx));
            }
        }

        let map = self
            .load_kfunc_stack_slot_base_arg_map()
            .unwrap_or_default();
        let requires_base = map
            .get(kfunc_name)
            .is_some_and(|args| args.contains(&arg_idx));

        let mut cache = self.kfunc_stack_slot_base_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        requires_base
    }

    /// Returns whether `kfunc_name` pointer arg appears to be an output parameter by name.
    pub fn kfunc_pointer_arg_is_named_out(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_out_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|args| args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_out_pointer_arg_map().unwrap_or_default();
        let is_named_out = map
            .get(kfunc_name)
            .is_some_and(|args| args.contains(&arg_idx));

        let mut cache = self.kfunc_out_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_named_out
    }

    /// Returns whether `kfunc_name` pointer arg appears to be an input parameter by name.
    pub fn kfunc_pointer_arg_is_named_in(&self, kfunc_name: &str, arg_idx: usize) -> bool {
        {
            let cache = self.kfunc_in_pointer_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .is_some_and(|args| args.contains(&arg_idx));
            }
        }

        let map = self.load_kfunc_in_pointer_arg_map().unwrap_or_default();
        let is_named_in = map
            .get(kfunc_name)
            .is_some_and(|args| args.contains(&arg_idx));

        let mut cache = self.kfunc_in_pointer_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        is_named_in
    }

    /// Returns the inferred stack-object pointee type name for a pointer argument, if any.
    pub fn kfunc_pointer_arg_stack_object_type_name(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> Option<String> {
        {
            let cache = self.kfunc_stack_object_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
                    .map(|(_, _, type_name)| type_name.clone());
            }
        }

        let map = self.load_kfunc_stack_object_arg_map().unwrap_or_default();
        let type_name = map
            .get(kfunc_name)
            .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
            .map(|(_, _, type_name)| type_name.clone());

        let mut cache = self.kfunc_stack_object_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        type_name
    }

    /// Returns the inferred stack-object pointee type ID for a pointer argument, if any.
    pub fn kfunc_pointer_arg_stack_object_type_id(
        &self,
        kfunc_name: &str,
        arg_idx: usize,
    ) -> Option<u32> {
        {
            let cache = self.kfunc_stack_object_arg_cache.read().unwrap();
            if let Some(map) = cache.as_ref() {
                return map
                    .get(kfunc_name)
                    .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
                    .map(|(_, type_id, _)| *type_id);
            }
        }

        let map = self.load_kfunc_stack_object_arg_map().unwrap_or_default();
        let type_id = map
            .get(kfunc_name)
            .and_then(|args| args.iter().find(|(idx, _, _)| *idx == arg_idx))
            .map(|(_, type_id, _)| *type_id);

        let mut cache = self.kfunc_stack_object_arg_cache.write().unwrap();
        if cache.is_none() {
            *cache = Some(map);
        }

        type_id
    }
}
