#[derive(Clone, Copy)]
pub(super) enum ContextWriteScannerForm {
    Direct,
    RecordAlias,
    ReturnedContextAlias,
    RecordWrapper,
    RecordSpread,
    UserFunctionRecordWrapper,
    NestedUserFunctionRecordWrapper,
    RecordInsert,
    RecordUpdate,
    RecordUpsert,
    RecordGetAlias,
    RecordPipelineGetAlias,
    UserFunctionRecordGetAlias,
    UserFunctionRecordPipelineGetAlias,
    RecordSelect,
    RecordReject,
    RecordRename,
    RecordMerge,
    RecordDefault,
}

impl ContextWriteScannerForm {
    pub(super) const ALL: [Self; 19] = [
        Self::Direct,
        Self::RecordAlias,
        Self::ReturnedContextAlias,
        Self::RecordWrapper,
        Self::RecordSpread,
        Self::UserFunctionRecordWrapper,
        Self::NestedUserFunctionRecordWrapper,
        Self::RecordInsert,
        Self::RecordUpdate,
        Self::RecordUpsert,
        Self::RecordGetAlias,
        Self::RecordPipelineGetAlias,
        Self::UserFunctionRecordGetAlias,
        Self::UserFunctionRecordPipelineGetAlias,
        Self::RecordSelect,
        Self::RecordReject,
        Self::RecordRename,
        Self::RecordMerge,
        Self::RecordDefault,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::RecordAlias => "record-alias",
            Self::ReturnedContextAlias => "returned-context-alias",
            Self::RecordWrapper => "record-wrapper",
            Self::RecordSpread => "record-spread",
            Self::UserFunctionRecordWrapper => "user-function-record-wrapper",
            Self::NestedUserFunctionRecordWrapper => "nested-user-function-record-wrapper",
            Self::RecordInsert => "record-insert",
            Self::RecordUpdate => "record-update",
            Self::RecordUpsert => "record-upsert",
            Self::RecordGetAlias => "record-get-alias",
            Self::RecordPipelineGetAlias => "record-pipeline-get-alias",
            Self::UserFunctionRecordGetAlias => "user-function-record-get-alias",
            Self::UserFunctionRecordPipelineGetAlias => "user-function-record-pipeline-get-alias",
            Self::RecordSelect => "record-select",
            Self::RecordReject => "record-reject",
            Self::RecordRename => "record-rename",
            Self::RecordMerge => "record-merge",
            Self::RecordDefault => "record-default",
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::Direct => "$ctx",
            Self::RecordAlias | Self::ReturnedContextAlias => "$event",
            Self::RecordGetAlias
            | Self::RecordPipelineGetAlias
            | Self::UserFunctionRecordGetAlias
            | Self::UserFunctionRecordPipelineGetAlias => "$event",
            Self::RecordWrapper
            | Self::RecordSpread
            | Self::UserFunctionRecordWrapper
            | Self::NestedUserFunctionRecordWrapper
            | Self::RecordInsert
            | Self::RecordUpdate
            | Self::RecordUpsert
            | Self::RecordSelect
            | Self::RecordReject
            | Self::RecordMerge
            | Self::RecordDefault => "$rec.event",
            Self::RecordRename => "$rec.alias",
        }
    }
}

pub(super) fn context_write_scanner_assignment(
    field_name: &str,
    indexed: bool,
    form: ContextWriteScannerForm,
) -> String {
    let root = form.root();
    let assignment = if field_name == "flow_keys" {
        format!("  {root}.{field_name}.ip_proto = 6")
    } else if indexed {
        format!("  {root}.{field_name}.0 = 42")
    } else if matches!(field_name, "new_value" | "sysctl_new_value" | "sun_path") {
        format!("  {root}.{field_name} = \"1\"")
    } else {
        format!("  {root}.{field_name} = 1")
    };

    assignment
}

pub(super) fn context_write_scanner_source_from_assignments(
    assignments: &[String],
    form: ContextWriteScannerForm,
) -> String {
    let assignments = assignments.join("\n");
    match form {
        ContextWriteScannerForm::Direct => format!("{{|ctx|\n{assignments}\n  \"allow\"\n}}"),
        ContextWriteScannerForm::RecordAlias => {
            format!("{{|ctx|\n  mut event = $ctx\n{assignments}\n  \"allow\"\n}}")
        }
        ContextWriteScannerForm::ReturnedContextAlias => format!(
            "{{|ctx|\n  def id [event] {{ $event }}\n  mut event = (id $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordWrapper => {
            format!("{{|ctx|\n  mut rec = {{ event: $ctx }}\n{assignments}\n  \"allow\"\n}}")
        }
        ContextWriteScannerForm::RecordSpread => format!(
            "{{|ctx|\n  let base = {{ event: $ctx }}\n  mut rec = {{ ok: true, ...$base }}\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordWrapper => format!(
            "{{|ctx|\n  def wrap [event] {{ {{ event: $event }} }}\n  mut rec = (wrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::NestedUserFunctionRecordWrapper => format!(
            "{{|ctx|\n  def wrap [event] {{ {{ event: $event }} }}\n  def outer [event] {{ wrap $event }}\n  mut rec = (outer $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordInsert => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | insert event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordUpdate => format!(
            "{{|ctx|\n  mut rec = ({{ event: 0 }} | update event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordUpsert => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | upsert event $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordGetAlias => format!(
            "{{|ctx|\n  let rec = {{ event: $ctx }}\n  mut event = ($rec | get event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordPipelineGetAlias => format!(
            "{{|ctx|\n  mut event = ({{ other: 1 }} | insert event $ctx | get event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordGetAlias => format!(
            "{{|ctx|\n  def unwrap [event] {{\n    let rec = {{ event: $event }}\n    $rec | get event\n  }}\n  mut event = (unwrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::UserFunctionRecordPipelineGetAlias => format!(
            "{{|ctx|\n  def unwrap [event] {{\n    {{ other: 1 }} | insert event $event | get event\n  }}\n  mut event = (unwrap $ctx)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordSelect => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx, other: 1 }} | select event)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordReject => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx, other: 1 }} | reject other)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordRename => format!(
            "{{|ctx|\n  mut rec = ({{ event: $ctx }} | rename alias)\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordMerge => format!(
            "{{|ctx|\n  mut rec = ({{ other: 1 }} | merge {{ event: $ctx }})\n{assignments}\n  \"allow\"\n}}"
        ),
        ContextWriteScannerForm::RecordDefault => format!(
            "{{|ctx|\n  mut rec = ({{ }} | default $ctx event)\n{assignments}\n  \"allow\"\n}}"
        ),
    }
}

pub(super) fn context_write_scanner_source(
    field_name: &str,
    indexed: bool,
    form: ContextWriteScannerForm,
) -> String {
    context_write_scanner_source_from_assignments(
        &[context_write_scanner_assignment(field_name, indexed, form)],
        form,
    )
}
