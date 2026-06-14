use super::*;
use crate::compiler::mir::StructField;
use crate::compiler::subfn_summaries::infer_subfunction_summaries;
use crate::compiler::test_mir_builders::{
    ExplicitNullRefKfuncCase, copy_from_user_dynptr_join_reinitialize_mir,
    copy_from_user_task_dynptr_join_reinitialize_mir, dynptr_clone_join_reinitialize_mir,
    explicit_null_ref_join_release_mir, packet_dynptr_kfunc_join_reinitialize_mir,
    unknown_stack_object_conditional_init_blocks_reinitialize_mir,
    unknown_stack_object_copy_initializes_destination_mir,
    unknown_stack_object_init_blocks_reinitialize_mir, unknown_stack_object_lifecycle_composes_mir,
    xdp_get_xfrm_state_explicit_null_join_mir,
};
use crate::compiler::{EbpfProgramType, ProbeContext};

include!("kfuncs/explicit_refs_and_graph.rs");
include!("kfuncs/dynptr_and_stack_objects.rs");
include!("kfuncs/scx_buffers_and_iterator_args.rs");
include!("kfuncs/iterator_lifecycle.rs");
include!("kfuncs/task_cgroup_crypto_refs.rs");
include!("kfuncs/graph_object_refs.rs");
include!("kfuncs/locks_wq_and_preempt.rs");
include!("kfuncs/crypto_dynptr_and_metadata.rs");
