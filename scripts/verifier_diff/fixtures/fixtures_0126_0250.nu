const VERIFIER_DIFF_FIXTURES_0126_0250 = [
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
    {
        name: "fentry-array-element-context"
        category: "tracing"
        tags: [fentry context array]
        requires: [kernel-btf]
        target: "fentry:wake_up_new_task"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.comm.0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-sleepable-context"
        category: "tracing"
        tags: [fentry sleepable context]
        requires: [kernel-btf]
        target: "fentry.s:security_file_open"
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
        name: "fexit-context"
        category: "tracing"
        tags: [fexit context]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fexit-func-arg-ret-helper-calls"
        category: "tracing"
        tags: [fexit helper-call context source metadata]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  let arg0 = "01234567"'
            '  let retval = "01234567"'
            '  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count'
            '  (helper-call "bpf_get_func_ret" $ctx $retval) | count'
            '  (helper-call "bpf_get_func_arg_cnt" $ctx) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-func-ret-helper-reject"
        category: "tracing"
        tags: [fentry helper-call context reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let retval = "01234567"'
            '  helper-call "bpf_get_func_ret" $ctx $retval'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_func_ret' is only valid in fexit and fmod_ret programs"
    }
    {
        name: "fentry-missing-target-help-reject"
        category: "tracing"
        tags: [fentry context diagnostic reject]
        requires: [kernel-btf]
        target: "fentry:nu_plugin_ebpf_missing_function_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "target signature"
    }
    {
        name: "fexit-sleepable-context"
        category: "tracing"
        tags: [fexit sleepable context]
        requires: [kernel-btf]
        target: "fexit.s:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-context"
        category: "tracing"
        tags: [fmod-ret context]
        requires: [kernel-btf]
        target: "fmod_ret:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-sleepable-context"
        category: "tracing"
        tags: [fmod-ret sleepable context]
        requires: [kernel-btf]
        target: "fmod_ret.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-context"
        category: "tracing"
        tags: [lsm context]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-sleepable-context"
        category: "tracing"
        tags: [lsm sleepable context]
        requires: [kernel-btf]
        target: "lsm.s:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-bound-arg-context"
        category: "tracing"
        tags: [lsm context alias]
        requires: [kernel-btf]
        target: "lsm:file_open"
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
    {
        name: "lsm-missing-target-help-reject"
        category: "tracing"
        tags: [lsm context diagnostic reject]
        requires: [kernel-btf]
        target: "lsm:nu_plugin_ebpf_missing_hook_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "LSM hook name"
    }
    {
        name: "lsm-cgroup-context"
        category: "tracing"
        tags: [lsm-cgroup context]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg2 + $ctx.arg_count + $ctx.pid) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg_count is only available on BTF-backed tracing contexts with bpf_get_func_arg_cnt support"
    }
    {
        name: "lsm-cgroup-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-helper-context"
        category: "tracing"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  helper-call "bpf_sys_close" 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-context"
        category: "tracing"
        tags: [freplace context]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-rejects-context-field"
        category: "context-policy"
        tags: [syscall context reject]
        target: "syscall:demo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on syscall programs"
    }
    {
        name: "freplace-rejects-arg-context"
        category: "context-policy"
        tags: [freplace context reject]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg0 is only available on contexts with argument access"
    }
    {
        name: "xdp-packet-count"
        category: "packet"
        tags: [xdp counter]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-derived-header-fields"
        category: "packet"
        tags: [xdp packet header bitfield source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let ip4 = ($ctx.data.eth.ipv4.version + $ctx.data.eth.ipv4.ihl + $ctx.data.eth.ipv4.dscp + $ctx.data.eth.ipv4.ecn + $ctx.data.eth.ipv4.flags + $ctx.data.eth.ipv4.dont_fragment + $ctx.data.eth.ipv4.more_fragments + $ctx.data.eth.ipv4.fragment_offset)'
            '  let ip6 = ($ctx.data.eth.ipv6.version + $ctx.data.eth.ipv6.traffic_class + $ctx.data.eth.ipv6.flow_label)'
            '  let tcp = ($ctx.data.eth.ipv4.tcp.data_offset + $ctx.data.eth.ipv4.tcp.flags + $ctx.data.eth.ipv4.tcp.syn)'
            '  ($ip4 + $ip6 + $tcp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-bitfield-writes"
        category: "packet"
        tags: [xdp packet header bitfield write source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.ipv4.version = 4'
            '  $ctx.data.eth.ipv4.flags = 2'
            '  $ctx.data.eth.ipv4.tcp.syn = 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-arp-header-fields"
        category: "packet"
        tags: [xdp packet header arp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let arp = ($ctx.data.eth.arp.hardware_type + $ctx.data.eth.arp.protocol_type + $ctx.data.eth.arp.hardware_len + $ctx.data.eth.arp.protocol_len + $ctx.data.eth.arp.opcode)'
            '  $arp | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-header-field-aliases"
        category: "packet"
        tags: [xdp packet header alias source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let eth = $ctx.data.eth.h_proto'
            '  let ip4 = ($ctx.data.eth.ipv4.tot_len + $ctx.data.eth.ipv4.saddr.0 + $ctx.data.eth.ipv4.daddr.0)'
            '  let udp = ($ctx.data.eth.ipv4.udp.source + $ctx.data.eth.ipv4.udp.dest)'
            '  ($eth + $ip4 + $udp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-icmp-echo-fields"
        category: "packet"
        tags: [xdp packet header icmp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let icmp4 = ($ctx.data.eth.ipv4.icmp.rest_of_header + $ctx.data.eth.ipv4.icmp.echo_id + $ctx.data.eth.ipv4.icmp.echo_sequence)'
            '  let icmp6 = ($ctx.data.eth.ipv6.icmpv6.rest + $ctx.data.eth.ipv6.icmpv6.identifier + $ctx.data.eth.ipv6.icmpv6.sequence)'
            '  ($icmp4 + $icmp6) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-frags-driver-context"
        category: "context-surface"
        tags: [xdp context frags]
        requires: [loopback-interface]
        target: "xdp:lo:drv:frags"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.rx_queue_index + $ctx.xdp_buff_len + $ctx.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-devmap-secondary-context"
        category: "program-model"
        tags: [xdp devmap context]
        target: "xdp:devmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.egress_ifindex) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-cpumap-secondary-context"
        category: "program-model"
        tags: [xdp cpumap context]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.rx_queue_index) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-egress-target-metadata"
        category: "program-model"
        tags: [tcx metadata]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-peer-target-metadata"
        category: "program-model"
        tags: [netkit metadata]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-target-metadata"
        category: "program-model"
        tags: [flow-dissector metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netfilter-defrag-target-metadata"
        category: "program-model"
        tags: [netfilter metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-target-metadata"
        category: "program-model"
        tags: [lwt metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-migrate-target-metadata"
        category: "program-model"
        tags: [sk-reuseport metadata migrate]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-target-metadata"
        category: "program-model"
        tags: [cgroup-sock-addr metadata unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-target-metadata"
        category: "program-model"
        tags: [syscall metadata]
        target: "syscall:demo"
        program: [
            '{||'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-target-metadata"
        category: "program-model"
        tags: [freplace metadata]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-vma-target-metadata"
        category: "program-model"
        tags: [iter metadata task-vma]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-get-null-checked"
        category: "maps"
        tags: [hash-map null-check]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash'
            '  let entry = (0 | map-get seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-direct-pointer-branch"
        category: "maps"
        tags: [hash-map null-check branch]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put direct_seen_args 0 --kind hash'
            '  let entry = (0 | map-get direct_seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-record-key-put-get"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed --kind hash --key-type "record{pid:int,cookie:int}" --value-type int'
            '  let key = { pid: 1, cookie: 7 }'
            '  42 | map-put keyed $key --kind hash'
            '  let entry = ($key | map-get keyed --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-aligned-record-key-put-get"
        category: "maps"
        tags: [maps map-define records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_aligned --kind hash --key-type "record{tag:int,flag:bool}" --value-type int'
            '  let key = { tag: 7, flag: true }'
            '  42 | map-put keyed_aligned $key --kind hash'
            '  let entry = ($key | map-get keyed_aligned --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-key-put-get"
        category: "maps"
        tags: [maps map-define records arrays map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches --kind hash --key-type "array{record{pid:int,cpu:int}:2}" --value-type int'
            '  let put_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  42 | map-put keyed_batches $put_key --kind hash'
            '  let get_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  let entry = ($get_key | map-get keyed_batches --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-key-contains-delete"
        category: "maps"
        tags: [maps map-define records arrays map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches_ops --kind hash --key-type "array{record{pid:int,cpu:int}:2}" --value-type int'
            '  let put_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  42 | map-put keyed_batches_ops $put_key --kind hash'
            '  let contains_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  if (map-contains keyed_batches_ops $contains_key --kind hash) {'
            '    let delete_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '    map-delete keyed_batches_ops $delete_key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-value-type-invalid-array-length-rejects-context"
        category: "maps"
        tags: [maps map-define arrays diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "array{u32:x}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'array{u32:x}' has an invalid array length"
    }
    {
        name: "map-define-graph-root-payload-unmatched-braces-rejects-context"
        category: "maps"
        tags: [maps map-define graph diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:bpf_refcount"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'bpf_list_head:node_data:node:record{refs:bpf_refcount' has unmatched '{' braces"
    }
    {
        name: "map-define-value-type-invalid-graph-root-field-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node-field,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node-field' requires a valid node field name"
    }
    {
        name: "map-define-value-type-graph-root-payload-non-record-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:u64,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node:u64' requires the object payload schema to be record{...}"
    }
    {
        name: "map-define-value-type-graph-root-payload-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph records bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64},count:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root.refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
    {
        name: "map-define-value-type-top-level-graph-root-payload-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
    {
        name: "map-define-key-type-duplicate-record-field-rejects-path"
        category: "maps"
        tags: [maps map-define records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define dup_keys --kind hash --key-type "record{pid:u32,pid:u64}" --value-type int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'pid' is duplicated in type spec 'record{pid:u32,pid:u64}'"
    }
    {
        name: "map-define-value-type-invalid-kptr-field-rejects-path"
        category: "maps"
        tags: [maps map-define records kptr diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define state --kind hash --value-type "record{task:kptr:task-struct}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'task' type spec 'kptr:task-struct' requires a kernel struct type name"
    }
    {
        name: "annotated-mut-record-alignment"
        category: "globals"
        tags: [globals records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<tag: bool count: int> = { tag: true, count: 7 }'
            '  $state.count | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-empty-zero-init"
        category: "globals"
        tags: [globals records zero-init accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-scalar-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals scalar "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = null'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected int, found nothing"
    }
    {
        name: "annotated-mut-record-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = null'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found nothing"
    }
    {
        name: "annotated-mut-record-nested-empty-zero-fill"
        category: "globals"
        tags: [globals records zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 stats: {} }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-nested-extra-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<stats: record<hits: int>> = { stats: { hits: 7 extra: true } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unexpected record field 'stats.extra'"
    }
    {
        name: "annotated-mut-list-spread-initializer"
        category: "globals"
        tags: [globals list list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut vals: list<int> = [1, ...[2, 3]]'
            '  ($vals | get 2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-string-field-count"
        category: "globals"
        tags: [globals records string accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<comm: string pid: int> = { comm: "hi" pid: 7 }'
            '  $state.comm | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-inline-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...[{ pid: 9 cpu: 3 }]]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-bound-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...$tail]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-top-level-record-omission-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found record<pid: int>"
    }
]
