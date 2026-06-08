const VERIFIER_DIFF_FIXTURES_0126_0187 = [
    {
        name: "tracepoint-memfd-secret-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_memfd_secret]
        target: "tracepoint:syscalls/sys_enter_memfd_secret"
        program: [
            '{|ctx|'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-gettimeofday-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_gettimeofday"
        program: [
            '{|ctx|'
            '  let tv = $ctx.tv'
            '  let tz = $ctx.tz'
            '  if $tv { 1 | count }'
            '  if $tz { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-utimensat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_utimensat]
        target: "tracepoint:syscalls/sys_enter_utimensat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let utimes = $ctx.utimes'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $utimes { 1 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-clock-gettime-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_clock_gettime"
        program: [
            '{|ctx|'
            '  $ctx.which_clock | count'
            '  let tp = $ctx.tp'
            '  if $tp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-timer-create-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_timer_create"
        program: [
            '{|ctx|'
            '  $ctx.which_clock | count'
            '  let event = $ctx.timer_event_spec'
            '  let created = $ctx.created_timer_id'
            '  if $event { 1 | count }'
            '  if $created { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-timerfd-settime-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_timerfd_settime"
        program: [
            '{|ctx|'
            '  ($ctx.ufd + $ctx.flags) | count'
            '  let utmr = $ctx.utmr'
            '  let otmr = $ctx.otmr'
            '  if $utmr { 1 | count }'
            '  if $otmr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-uring-setup-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_uring_setup]
        target: "tracepoint:syscalls/sys_enter_io_uring_setup"
        program: [
            '{|ctx|'
            '  $ctx.entries | count'
            '  let params = $ctx.params'
            '  if $params { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-uring-enter-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_uring_enter]
        target: "tracepoint:syscalls/sys_enter_io_uring_enter"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.to_submit + $ctx.min_complete + $ctx.flags + $ctx.sigsz) | count'
            '  let sig = $ctx.sig'
            '  if $sig { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-uring-register-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_uring_register]
        target: "tracepoint:syscalls/sys_enter_io_uring_register"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.opcode + $ctx.nr_args) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-kill-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_kill"
        program: [
            '{|ctx|'
            '  $ctx.sig | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-rt-sigaction-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_rt_sigaction"
        program: [
            '{|ctx|'
            '  ($ctx.sig + $ctx.sigsetsize) | count'
            '  let act = $ctx.act'
            '  let oact = $ctx.oact'
            '  if $act { 1 | count }'
            '  if $oact { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-rt-sigtimedwait-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_rt_sigtimedwait"
        program: [
            '{|ctx|'
            '  $ctx.sigsetsize | count'
            '  let uthese = $ctx.uthese'
            '  let uinfo = $ctx.uinfo'
            '  let uts = $ctx.uts'
            '  if $uthese { 1 | count }'
            '  if $uinfo { 1 | count }'
            '  if $uts { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pidfd-send-signal-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_pidfd_send_signal"
        program: [
            '{|ctx|'
            '  ($ctx.pidfd + $ctx.sig + $ctx.flags) | count'
            '  let info = $ctx.info'
            '  if $info { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pidfd-open-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pidfd_open]
        target: "tracepoint:syscalls/sys_enter_pidfd_open"
        program: [
            '{|ctx|'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pidfd-getfd-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pidfd_getfd]
        target: "tracepoint:syscalls/sys_enter_pidfd_getfd"
        program: [
            '{|ctx|'
            '  ($ctx.pidfd + $ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-create-ruleset-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_create_ruleset]
        target: "tracepoint:syscalls/sys_enter_landlock_create_ruleset"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr'
            '  if $attr { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-add-rule-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_add_rule]
        target: "tracepoint:syscalls/sys_enter_landlock_add_rule"
        program: [
            '{|ctx|'
            '  let rule_attr = $ctx.rule_attr'
            '  if $rule_attr { 1 | count }'
            '  ($ctx.ruleset_fd + $ctx.rule_type + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-restrict-self-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_restrict_self]
        target: "tracepoint:syscalls/sys_enter_landlock_restrict_self"
        program: [
            '{|ctx|'
            '  ($ctx.ruleset_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-get-self-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_get_self_attr]
        target: "tracepoint:syscalls/sys_enter_lsm_get_self_attr"
        program: [
            '{|ctx|'
            '  let lsm_ctx = $ctx.ctx'
            '  let size = $ctx.size'
            '  if $lsm_ctx { 1 | count }'
            '  if $size { 1 | count }'
            '  ($ctx.attr + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-set-self-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_set_self_attr]
        target: "tracepoint:syscalls/sys_enter_lsm_set_self_attr"
        program: [
            '{|ctx|'
            '  let lsm_ctx = $ctx.ctx'
            '  if $lsm_ctx { 1 | count }'
            '  ($ctx.attr + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-list-modules-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_list_modules]
        target: "tracepoint:syscalls/sys_enter_lsm_list_modules"
        program: [
            '{|ctx|'
            '  let ids = $ctx.ids'
            '  let size = $ctx.size'
            '  if $ids { 1 | count }'
            '  if $size { 1 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setresuid-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setresuid"
        program: [
            '{|ctx|'
            '  ($ctx.ruid + $ctx.euid + $ctx.suid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getresgid-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_getresgid"
        program: [
            '{|ctx|'
            '  let rgidp = $ctx.rgidp'
            '  let egidp = $ctx.egidp'
            '  let sgidp = $ctx.sgidp'
            '  if $rgidp { 1 | count }'
            '  if $egidp { 1 | count }'
            '  if $sgidp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setgroups-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setgroups"
        program: [
            '{|ctx|'
            '  $ctx.gidsetsize | count'
            '  let grouplist = $ctx.grouplist'
            '  if $grouplist { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-capset-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_capset"
        program: [
            '{|ctx|'
            '  let header = $ctx.header'
            '  let data = $ctx.data'
            '  if $header { 1 | count }'
            '  if $data { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-prctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_prctl"
        program: [
            '{|ctx|'
            '  ($ctx.option + ($ctx.args | get 1)) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-setscheduler-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_setscheduler]
        target: "tracepoint:syscalls/sys_enter_sched_setscheduler"
        program: [
            '{|ctx|'
            '  $ctx.policy | count'
            '  let param = $ctx.param'
            '  if $param { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-setaffinity-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_setaffinity]
        target: "tracepoint:syscalls/sys_enter_sched_setaffinity"
        program: [
            '{|ctx|'
            '  $ctx.len | count'
            '  let mask = $ctx.user_mask_ptr'
            '  if $mask { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-getattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_getattr]
        target: "tracepoint:syscalls/sys_enter_sched_getattr"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.flags) | count'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-rr-get-interval-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_rr_get_interval]
        target: "tracepoint:syscalls/sys_enter_sched_rr_get_interval"
        program: [
            '{|ctx|'
            '  let interval = $ctx.interval'
            '  if $interval { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-nice-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_nice]
        target: "tracepoint:syscalls/sys_enter_nice"
        program: [
            '{|ctx|'
            '  $ctx.increment | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-msgctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_msgctl]
        target: "tracepoint:syscalls/sys_enter_msgctl"
        program: [
            '{|ctx|'
            '  $ctx.cmd | count'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-msgrcv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_msgrcv]
        target: "tracepoint:syscalls/sys_enter_msgrcv"
        program: [
            '{|ctx|'
            '  ($ctx.msgsz + $ctx.msgtyp + $ctx.msgflg) | count'
            '  let msgp = $ctx.msgp'
            '  if $msgp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-semctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_semctl]
        target: "tracepoint:syscalls/sys_enter_semctl"
        program: [
            '{|ctx|'
            '  ($ctx.semid + $ctx.semnum + $ctx.cmd) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-semtimedop-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_semtimedop]
        target: "tracepoint:syscalls/sys_enter_semtimedop"
        program: [
            '{|ctx|'
            '  $ctx.nsops | count'
            '  let tsops = $ctx.tsops'
            '  let timeout = $ctx.timeout'
            '  if $tsops { 1 | count }'
            '  if $timeout { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-shmctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_shmctl]
        target: "tracepoint:syscalls/sys_enter_shmctl"
        program: [
            '{|ctx|'
            '  $ctx.cmd | count'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-shmat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_shmat]
        target: "tracepoint:syscalls/sys_enter_shmat"
        program: [
            '{|ctx|'
            '  $ctx.shmflg | count'
            '  let shmaddr = $ctx.shmaddr'
            '  if $shmaddr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex]
        target: "tracepoint:syscalls/sys_enter_futex"
        program: [
            '{|ctx|'
            '  let uaddr = $ctx.uaddr'
            '  let utime = $ctx.utime'
            '  let uaddr2 = $ctx.uaddr2'
            '  if $uaddr { 1 | count }'
            '  if $utime { 1 | count }'
            '  if $uaddr2 { 1 | count }'
            '  ($ctx.op + $ctx.val + $ctx.val3) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-waitv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_waitv]
        target: "tracepoint:syscalls/sys_enter_futex_waitv"
        program: [
            '{|ctx|'
            '  let waiters = $ctx.waiters'
            '  let timeout = $ctx.timeout'
            '  if $waiters { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.nr_futexes + $ctx.flags + $ctx.clockid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-wake-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_wake]
        target: "tracepoint:syscalls/sys_enter_futex_wake"
        program: [
            '{|ctx|'
            '  let uaddr = $ctx.uaddr'
            '  if $uaddr { 1 | count }'
            '  ($ctx.mask + $ctx.nr + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-wait-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_wait]
        target: "tracepoint:syscalls/sys_enter_futex_wait"
        program: [
            '{|ctx|'
            '  let uaddr = $ctx.uaddr'
            '  let timeout = $ctx.timeout'
            '  if $uaddr { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.val + $ctx.mask + $ctx.flags + $ctx.clockid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-requeue-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_requeue]
        target: "tracepoint:syscalls/sys_enter_futex_requeue"
        program: [
            '{|ctx|'
            '  let waiters = $ctx.waiters'
            '  if $waiters { 1 | count }'
            '  ($ctx.flags + $ctx.nr_wake + $ctx.nr_requeue) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-arch-prctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_arch_prctl]
        target: "tracepoint:syscalls/sys_enter_arch_prctl"
        program: [
            '{|ctx|'
            '  $ctx.option | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-ioperm-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ioperm]
        target: "tracepoint:syscalls/sys_enter_ioperm"
        program: [
            '{|ctx|'
            '  ($ctx.from + $ctx.num + $ctx.turn_on) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-iopl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_iopl]
        target: "tracepoint:syscalls/sys_enter_iopl"
        program: [
            '{|ctx|'
            '  $ctx.level | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-modify-ldt-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_modify_ldt]
        target: "tracepoint:syscalls/sys_enter_modify_ldt"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.ptr'
            '  if $ptr { 1 | count }'
            '  ($ctx.func + $ctx.bytecount) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-rt-sigreturn-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_rt_sigreturn]
        target: "tracepoint:syscalls/sys_enter_rt_sigreturn"
        program: [
            '{|ctx|'
            '  $ctx.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-map-shadow-stack-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_map_shadow_stack]
        target: "tracepoint:syscalls/sys_enter_map_shadow_stack"
        program: [
            '{|ctx|'
            '  ($ctx.addr + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-kcmp-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_kcmp]
        target: "tracepoint:syscalls/sys_enter_kcmp"
        program: [
            '{|ctx|'
            '  ($ctx.pid1 + $ctx.pid2 + $ctx.type + $ctx.idx1 + $ctx.idx2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-cachestat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_cachestat]
        target: "tracepoint:syscalls/sys_enter_cachestat"
        program: [
            '{|ctx|'
            '  let cstat_range = $ctx.cstat_range'
            '  let cstat = $ctx.cstat'
            '  if $cstat_range { 1 | count }'
            '  if $cstat { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mseal-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mseal]
        target: "tracepoint:syscalls/sys_enter_mseal"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-file-getattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_file_getattr]
        target: "tracepoint:syscalls/sys_enter_file_getattr"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let ufattr = $ctx.ufattr'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $ufattr { 1 | count }'
            '  ($ctx.dfd + $ctx.usize + $ctx.at_flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-file-setattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_file_setattr]
        target: "tracepoint:syscalls/sys_enter_file_setattr"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let ufattr = $ctx.ufattr'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $ufattr { 1 | count }'
            '  ($ctx.dfd + $ctx.usize + $ctx.at_flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-uretprobe-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_uretprobe]
        target: "tracepoint:syscalls/sys_enter_uretprobe"
        program: [
            '{|ctx|'
            '  $ctx.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-context"
        category: "tracing"
        tags: [perf-event context]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.sample_period + $ctx.addr + $ctx.perf_counter) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-pt-regs-arg-context"
        category: "context-surface"
        tags: [perf-event context pt-regs]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-hardware-frequency-context"
        category: "context-surface"
        tags: [perf-event context hardware freq]
        target: "perf_event:hardware:instructions:freq=99"
        program: [
            '{|ctx|'
            '  ($ctx.perf_counter + $ctx.perf_enabled + $ctx.perf_running + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tp-btf-context"
        category: "tracing"
        tags: [tp-btf context]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tp-btf-bound-arg-context"
        category: "tracing"
        tags: [tp-btf context alias]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let regs = $ctx.arg0'
            '  ($regs.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tp-btf-missing-target-help-reject"
        category: "tracing"
        tags: [tp-btf context diagnostic reject]
        requires: [kernel-btf]
        target: "tp_btf:nu_plugin_ebpf_missing_tracepoint_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "tracepoint name"
    }
    {
        name: "fentry-context"
        category: "tracing"
        tags: [fentry context]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-bound-arg-context"
        category: "tracing"
        tags: [fentry context alias]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  ($file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
