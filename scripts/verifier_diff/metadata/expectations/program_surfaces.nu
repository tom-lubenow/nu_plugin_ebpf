source ($EXPECTATIONS_DIR | path join program_surface_socket_redirect.nu)
source ($EXPECTATIONS_DIR | path join program_surface_packet_socket.nu)
source ($EXPECTATIONS_DIR | path join program_surface_tc_socket_write.nu)
source ($EXPECTATIONS_DIR | path join program_surface_sock_ops_write.nu)
source ($EXPECTATIONS_DIR | path join program_surface_socket_write.nu)
source ($EXPECTATIONS_DIR | path join program_surface_tc_context_write.nu)
source ($EXPECTATIONS_DIR | path join program_surface_sysctl_context_write.nu)
source ($EXPECTATIONS_DIR | path join program_surface_context_write.nu)
source ($EXPECTATIONS_DIR | path join program_surface_task_storage.nu)
source ($EXPECTATIONS_DIR | path join program_surface_object_storage.nu)
source ($EXPECTATIONS_DIR | path join program_surface_storage.nu)

let PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS = (
    $PROGRAM_SURFACE_PACKET_SOCKET_KERNEL_FEATURE_EXPECTATIONS
    | append $PROGRAM_SURFACE_CONTEXT_WRITE_KERNEL_FEATURE_EXPECTATIONS
    | append $PROGRAM_SURFACE_STORAGE_KERNEL_FEATURE_EXPECTATIONS
)
