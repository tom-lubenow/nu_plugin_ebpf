use crate::compiler::instruction::BpfHelper;
use crate::program_spec::{CgroupSockAddrTarget, CgroupSockTarget, ProgramSpec, TcTarget};

impl TcTarget {
    fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::RedirectPeer if !self.is_ingress() => Some(format!(
                "helper '{}' is only valid in tc ingress programs",
                helper.name()
            )),
            BpfHelper::SkAssign if !self.is_ingress() => Some(format!(
                "helper '{}' is only valid in tc ingress programs",
                helper.name()
            )),
            _ => None,
        }
    }
}

impl CgroupSockAddrTarget {
    fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match helper {
            BpfHelper::Bind if !self.is_connect() => Some(format!(
                "helper '{}' is only valid on cgroup_sock_addr connect4/connect6 hooks",
                helper.name()
            )),
            _ => None,
        }
    }
}

impl CgroupSockTarget {
    fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        let requires_post_bind = matches!(
            member_name,
            "src_ip4" | "src_ip6" | "src_port" | "dst_port" | "dst_ip4" | "dst_ip6"
        );
        if !requires_post_bind || self.is_post_bind() {
            return None;
        }
        Some(format!(
            "ctx.sk.{member_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
        ))
    }
}

impl ProgramSpec {
    fn attach_helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        match self {
            ProgramSpec::Tc { target } => target.helper_call_error(helper),
            ProgramSpec::CgroupSockAddr { target } => target.helper_call_error(helper),
            _ => None,
        }
    }

    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        self.program_type()
            .helper_call_error(helper)
            .or_else(|| self.attach_helper_call_error(helper))
    }

    pub(crate) fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        match self {
            ProgramSpec::CgroupSock { target } => {
                target.socket_projection_access_error(member_name)
            }
            _ => None,
        }
    }
}
