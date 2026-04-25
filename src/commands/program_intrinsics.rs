//! First-class eBPF closure commands that lower to program-family intrinsics.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value,
};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct AdjustPacket;

impl PluginCommand for AdjustPacket {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "adjust-packet"
    }

    fn description(&self) -> &str {
        "Adjust packet head, metadata, tail, pull, or room layout in supported packet programs."
    }

    fn signature(&self) -> Signature {
        Signature::build("adjust-packet")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .optional(
                "amount",
                SyntaxShape::Any,
                "Adjustment amount; otherwise uses pipeline input",
            )
            .switch("head", "Use the packet head adjust helper", None)
            .switch("meta", "Use the XDP metadata adjust helper", None)
            .switch("tail", "Use the packet tail adjust helper", None)
            .switch("pull", "Use skb pull_data linearization", None)
            .switch("room", "Use skb adjust_room", None)
            .named("mode", SyntaxShape::Int, "adjust_room mode", None)
            .named("flags", SyntaxShape::Int, "Raw helper flags", None)
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'xdp:lo' {|ctx| adjust-packet --head 0; 'pass' }",
            description: "Call the XDP head adjustment helper",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct AdjustMessage;

impl PluginCommand for AdjustMessage {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "adjust-message"
    }

    fn description(&self) -> &str {
        "Adjust sk_msg byte accounting or packet data in supported message programs."
    }

    fn signature(&self) -> Signature {
        Signature::build("adjust-message")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .optional(
                "first",
                SyntaxShape::Any,
                "First amount/start value; otherwise uses pipeline input",
            )
            .optional(
                "second",
                SyntaxShape::Any,
                "End or length for pull/push/pop",
            )
            .switch("apply", "Use bpf_msg_apply_bytes", None)
            .switch("cork", "Use bpf_msg_cork_bytes", None)
            .switch("pull", "Use bpf_msg_pull_data", None)
            .switch("push", "Use bpf_msg_push_data", None)
            .switch("pop", "Use bpf_msg_pop_data", None)
            .named("flags", SyntaxShape::Int, "Raw helper flags", None)
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'sk_msg:/sys/fs/bpf/sockmap' {|ctx| adjust-message --apply 8; 'pass' }",
            description: "Apply bytes in an sk_msg program",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct Redirect;

impl PluginCommand for Redirect {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "redirect"
    }

    fn description(&self) -> &str {
        "Redirect a packet to an interface, peer, or neighbor in supported packet programs."
    }

    fn signature(&self) -> Signature {
        Signature::build("redirect")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .optional(
                "ifindex",
                SyntaxShape::Any,
                "Interface index; otherwise uses pipeline input",
            )
            .switch("peer", "Use peer redirect where supported", None)
            .switch("neigh", "Use neighbor redirect where supported", None)
            .named("flags", SyntaxShape::Int, "Raw helper flags", None)
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'xdp:lo' {|ctx| redirect 1 }",
            description: "Redirect to ifindex 1",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct RedirectMap;

impl PluginCommand for RedirectMap {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "redirect-map"
    }

    fn description(&self) -> &str {
        "Redirect a packet through a named devmap/cpumap/xskmap-like BPF map."
    }

    fn signature(&self) -> Signature {
        Signature::build("redirect-map")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Redirect map name")
            .optional(
                "key",
                SyntaxShape::Any,
                "Map key; otherwise uses pipeline input",
            )
            .named("kind", SyntaxShape::String, "Redirect map kind", None)
            .named("flags", SyntaxShape::Int, "Raw helper flags", None)
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'xdp:lo' {|ctx| redirect-map tx_ports 0 --kind devmap }",
            description: "Redirect through a devmap-style map",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct RedirectSocket;

impl PluginCommand for RedirectSocket {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "redirect-socket"
    }

    fn description(&self) -> &str {
        "Redirect or select a socket through a named socket map."
    }

    fn signature(&self) -> Signature {
        Signature::build("redirect-socket")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .required("name", SyntaxShape::String, "Socket map name")
            .optional(
                "key",
                SyntaxShape::Any,
                "Socket map key; otherwise uses pipeline input",
            )
            .named("kind", SyntaxShape::String, "Socket map kind", None)
            .named("flags", SyntaxShape::Int, "Raw helper flags", None)
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'sk_skb:/sys/fs/bpf/sockmap' {|ctx| redirect-socket sockets 0 --kind sockmap }",
            description: "Redirect through a sockmap",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}

#[derive(Clone)]
pub struct AssignSocket;

impl PluginCommand for AssignSocket {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "assign-socket"
    }

    fn description(&self) -> &str {
        "Assign or clear a socket in tc/tcx ingress or sk_lookup programs."
    }

    fn signature(&self) -> Signature {
        Signature::build("assign-socket")
            .input_output_types(vec![(Type::Any, Type::Int), (Type::Nothing, Type::Int)])
            .optional(
                "socket",
                SyntaxShape::Any,
                "Socket pointer or 0; otherwise uses pipeline input",
            )
            .switch("replace", "Set BPF_SK_LOOKUP_F_REPLACE", None)
            .switch("no-reuseport", "Set BPF_SK_LOOKUP_F_NO_REUSEPORT", None)
            .named("flags", SyntaxShape::Int, "Raw sk_assign flags", None)
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --dry-run 'sk_lookup:/proc/self/ns/net' {|ctx| assign-socket 0 --replace }",
            description: "Clear a selected socket with replace semantics",
            result: None,
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        Ok(PipelineData::Value(Value::int(0, call.head), None))
    }
}
