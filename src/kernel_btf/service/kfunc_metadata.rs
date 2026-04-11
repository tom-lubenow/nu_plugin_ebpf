use std::collections::{HashMap, HashSet};

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
}
