const IPC_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["msgget"]
        fields: ["key" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgctl"]
        fields: ["msqid" "cmd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgsnd"]
        fields: ["msqid" "msgp" "msgsz" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgrcv"]
        fields: ["msqid" "msgp" "msgsz" "msgtyp" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["semget"]
        fields: ["key" "nsems" "semflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semctl"]
        fields: ["semid" "semnum" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semtimedop"]
        fields: ["semid" "tsops" "nsops" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semop"]
        fields: ["semid" "tsops" "nsops"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["shmget"]
        fields: ["key" "size" "shmflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmctl"]
        fields: ["shmid" "cmd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmat"]
        fields: ["shmid" "shmaddr" "shmflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmdt"]
        fields: ["shmaddr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
]
