use super::*;
use libc::{c_char, c_int, c_long, c_void};
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::os::fd::{FromRawFd, OwnedFd};
use std::ptr;
use std::sync::OnceLock;

#[repr(C)]
struct bpf_object {
    _private: [u8; 0],
}

#[repr(C)]
struct bpf_map {
    _private: [u8; 0],
}

#[repr(C)]
struct bpf_program {
    _private: [u8; 0],
}

#[repr(C)]
struct bpf_link {
    _private: [u8; 0],
}

#[repr(C)]
pub struct BpfNetfilterOpts {
    sz: usize,
    pf: u32,
    hooknum: u32,
    priority: i32,
    flags: u32,
}

impl BpfNetfilterOpts {
    pub fn new(pf: u32, hooknum: u32, priority: i32, flags: u32) -> Self {
        Self {
            sz: mem::size_of::<Self>(),
            pf,
            hooknum,
            priority,
            flags,
        }
    }
}

#[repr(C)]
pub struct BpfNetkitOpts {
    sz: usize,
    flags: u32,
    relative_fd: u32,
    relative_id: u32,
    expected_revision: u64,
}

impl BpfNetkitOpts {
    pub fn new() -> Self {
        Self {
            sz: mem::size_of::<Self>(),
            flags: 0,
            relative_fd: 0,
            relative_id: 0,
            expected_revision: 0,
        }
    }
}

type BpfObjectOpenMemFn =
    unsafe extern "C" fn(*const c_void, usize, *const c_void) -> *mut bpf_object;
type BpfObjectLoadFn = unsafe extern "C" fn(*mut bpf_object) -> c_int;
type BpfObjectCloseFn = unsafe extern "C" fn(*mut bpf_object);
type BpfObjectNextMapFn = unsafe extern "C" fn(*const bpf_object, *const bpf_map) -> *mut bpf_map;
type BpfObjectFindMapByNameFn =
    unsafe extern "C" fn(*const bpf_object, *const c_char) -> *mut bpf_map;
type BpfObjectFindProgramByNameFn =
    unsafe extern "C" fn(*const bpf_object, *const c_char) -> *mut bpf_program;
type BpfMapFdFn = unsafe extern "C" fn(*const bpf_map) -> c_int;
type BpfMapNameFn = unsafe extern "C" fn(*const bpf_map) -> *const c_char;
type BpfMapAttachStructOpsFn = unsafe extern "C" fn(*const bpf_map) -> *mut bpf_link;
type BpfProgramAttachRawTracepointFn =
    unsafe extern "C" fn(*const bpf_program, *const c_char) -> *mut bpf_link;
type BpfProgramAttachTraceFn = unsafe extern "C" fn(*const bpf_program) -> *mut bpf_link;
type BpfProgramAttachCgroupFn = unsafe extern "C" fn(*const bpf_program, c_int) -> *mut bpf_link;
type BpfProgramAttachNetfilterFn =
    unsafe extern "C" fn(*const bpf_program, *const BpfNetfilterOpts) -> *mut bpf_link;
type BpfProgramAttachNetkitFn =
    unsafe extern "C" fn(*const bpf_program, c_int, *const BpfNetkitOpts) -> *mut bpf_link;
type BpfProgramAttachNetnsFn = unsafe extern "C" fn(*const bpf_program, c_int) -> *mut bpf_link;
type BpfLinkDestroyFn = unsafe extern "C" fn(*mut bpf_link) -> c_int;
type LibbpfGetErrorFn = unsafe extern "C" fn(*const c_void) -> c_long;

struct LibbpfApi {
    _handle: *mut c_void,
    bpf_object_open_mem: BpfObjectOpenMemFn,
    bpf_object_load: BpfObjectLoadFn,
    bpf_object_close: BpfObjectCloseFn,
    bpf_object_next_map: BpfObjectNextMapFn,
    bpf_object_find_map_by_name: BpfObjectFindMapByNameFn,
    bpf_object_find_program_by_name: BpfObjectFindProgramByNameFn,
    bpf_map_fd: BpfMapFdFn,
    bpf_map_name: BpfMapNameFn,
    bpf_map_attach_struct_ops: BpfMapAttachStructOpsFn,
    bpf_program_attach_raw_tracepoint: BpfProgramAttachRawTracepointFn,
    bpf_program_attach_trace: BpfProgramAttachTraceFn,
    bpf_program_attach_cgroup: Option<BpfProgramAttachCgroupFn>,
    bpf_program_attach_netfilter: Option<BpfProgramAttachNetfilterFn>,
    bpf_program_attach_netkit: Option<BpfProgramAttachNetkitFn>,
    bpf_program_attach_netns: Option<BpfProgramAttachNetnsFn>,
    bpf_link_destroy: BpfLinkDestroyFn,
    libbpf_get_error: LibbpfGetErrorFn,
}

// SAFETY: `LibbpfApi` is immutable after initialization and contains only
// process-global function pointers and the dlopen handle kept alive for the
// duration of the process.
unsafe impl Send for LibbpfApi {}
unsafe impl Sync for LibbpfApi {}

static LIBBPF_API: OnceLock<Result<LibbpfApi, String>> = OnceLock::new();

fn libbpf_api() -> Result<&'static LibbpfApi, LoadError> {
    LIBBPF_API
        .get_or_init(LibbpfApi::load)
        .as_ref()
        .map_err(|msg| LoadError::Load(msg.clone()))
}

fn errno_message(errno: i32) -> String {
    io::Error::from_raw_os_error(errno).to_string()
}

fn negative_rc_message(context: &str, rc: c_int) -> LoadError {
    let errno = (-rc).max(1);
    LoadError::Load(format!("{context}: {}", errno_message(errno)))
}

fn pointer_error_message(context: &str, err: c_long) -> LoadError {
    let errno = (-err as i32).max(1);
    LoadError::Load(format!("{context}: {}", errno_message(errno)))
}

fn dl_last_error() -> String {
    // SAFETY: `dlerror` returns a thread-local error pointer owned by libc.
    let err = unsafe { libc::dlerror() };
    if err.is_null() {
        "unknown dlopen error".to_string()
    } else {
        // SAFETY: `dlerror` returns a valid NUL-terminated C string.
        unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned()
    }
}

impl LibbpfApi {
    fn load() -> Result<Self, String> {
        for soname in ["libbpf.so.1", "libbpf.so"] {
            let soname = CString::new(soname).expect("static soname must be valid");
            // SAFETY: `soname` is a valid NUL-terminated string. `dlopen` returns a process
            // handle or null on error.
            let handle =
                unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if handle.is_null() {
                continue;
            }

            return Ok(Self {
                _handle: handle,
                bpf_object_open_mem: Self::load_symbol(handle, b"bpf_object__open_mem\0")?,
                bpf_object_load: Self::load_symbol(handle, b"bpf_object__load\0")?,
                bpf_object_close: Self::load_symbol(handle, b"bpf_object__close\0")?,
                bpf_object_next_map: Self::load_symbol(handle, b"bpf_object__next_map\0")?,
                bpf_object_find_map_by_name: Self::load_symbol(
                    handle,
                    b"bpf_object__find_map_by_name\0",
                )?,
                bpf_object_find_program_by_name: Self::load_symbol(
                    handle,
                    b"bpf_object__find_program_by_name\0",
                )?,
                bpf_map_fd: Self::load_symbol(handle, b"bpf_map__fd\0")?,
                bpf_map_name: Self::load_symbol(handle, b"bpf_map__name\0")?,
                bpf_map_attach_struct_ops: Self::load_symbol(
                    handle,
                    b"bpf_map__attach_struct_ops\0",
                )?,
                bpf_program_attach_raw_tracepoint: Self::load_symbol(
                    handle,
                    b"bpf_program__attach_raw_tracepoint\0",
                )?,
                bpf_program_attach_trace: Self::load_symbol(
                    handle,
                    b"bpf_program__attach_trace\0",
                )?,
                bpf_program_attach_cgroup: Self::load_optional_symbol(
                    handle,
                    b"bpf_program__attach_cgroup\0",
                ),
                bpf_program_attach_netfilter: Self::load_optional_symbol(
                    handle,
                    b"bpf_program__attach_netfilter\0",
                ),
                bpf_program_attach_netkit: Self::load_optional_symbol(
                    handle,
                    b"bpf_program__attach_netkit\0",
                ),
                bpf_program_attach_netns: Self::load_optional_symbol(
                    handle,
                    b"bpf_program__attach_netns\0",
                ),
                bpf_link_destroy: Self::load_symbol(handle, b"bpf_link__destroy\0")?,
                libbpf_get_error: Self::load_symbol(handle, b"libbpf_get_error\0")?,
            });
        }

        Err("failed to load libbpf (expected libbpf.so.1 or libbpf.so)".to_string())
    }

    fn load_symbol<T>(handle: *mut c_void, symbol: &'static [u8]) -> Result<T, String> {
        let symbol_name = CStr::from_bytes_with_nul(symbol).expect("static symbol must be valid");
        // SAFETY: `handle` came from `dlopen`, `symbol_name` is a valid C string, and the
        // returned address is immediately converted into the expected function pointer type.
        unsafe {
            libc::dlerror();
        }
        let raw = unsafe { libc::dlsym(handle, symbol_name.as_ptr()) };
        if raw.is_null() {
            return Err(format!(
                "failed to resolve libbpf symbol '{}': {}",
                symbol_name.to_string_lossy(),
                dl_last_error()
            ));
        }
        Ok(unsafe { mem::transmute_copy(&raw) })
    }

    fn load_optional_symbol<T>(handle: *mut c_void, symbol: &'static [u8]) -> Option<T> {
        let symbol_name = CStr::from_bytes_with_nul(symbol).expect("static symbol must be valid");
        // SAFETY: `handle` came from `dlopen`, `symbol_name` is a valid C string, and the
        // returned address is immediately converted into the expected function pointer type.
        unsafe {
            libc::dlerror();
        }
        let raw = unsafe { libc::dlsym(handle, symbol_name.as_ptr()) };
        if raw.is_null() {
            None
        } else {
            Some(unsafe { mem::transmute_copy(&raw) })
        }
    }
}

fn duplicate_libbpf_map_fd(map_name: &str, fd: c_int) -> Result<OwnedFd, LoadError> {
    if fd < 0 {
        return Err(negative_rc_message(
            &format!("Failed to read file descriptor for libbpf map '{map_name}'"),
            fd,
        ));
    }

    // SAFETY: `fd` was returned by libbpf for a loaded BPF map. `dup` gives this loader
    // independent ownership so the Aya wrapper does not close libbpf's original descriptor.
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(LoadError::Load(format!(
            "Failed to duplicate libbpf map '{map_name}' fd: {}",
            io::Error::last_os_error()
        )));
    }

    // SAFETY: `dup_fd` is a fresh descriptor owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(dup_fd) })
}

fn aya_map_from_map_data(map_name: &str, map_data: MapData) -> Result<AyaMap, LoadError> {
    let map_type = map_data
        .info()
        .and_then(|info| info.map_type())
        .map_err(|error| {
            LoadError::Load(format!(
                "Failed to query libbpf map '{map_name}' metadata: {error}"
            ))
        })?;

    Ok(match map_type {
        MapType::Array => AyaMap::Array(map_data),
        MapType::BloomFilter => AyaMap::BloomFilter(map_data),
        MapType::CpuMap => AyaMap::CpuMap(map_data),
        MapType::DevMap => AyaMap::DevMap(map_data),
        MapType::DevMapHash => AyaMap::DevMapHash(map_data),
        MapType::Hash => AyaMap::HashMap(map_data),
        MapType::LpmTrie => AyaMap::LpmTrie(map_data),
        MapType::LruHash => AyaMap::LruHashMap(map_data),
        MapType::PerCpuArray => AyaMap::PerCpuArray(map_data),
        MapType::PerCpuHash => AyaMap::PerCpuHashMap(map_data),
        MapType::LruPerCpuHash => AyaMap::PerCpuLruHashMap(map_data),
        MapType::PerfEventArray => AyaMap::PerfEventArray(map_data),
        MapType::ProgramArray => AyaMap::ProgramArray(map_data),
        MapType::Queue => AyaMap::Queue(map_data),
        MapType::RingBuf => AyaMap::RingBuf(map_data),
        MapType::SockHash => AyaMap::SockHash(map_data),
        MapType::SockMap => AyaMap::SockMap(map_data),
        MapType::Stack => AyaMap::Stack(map_data),
        MapType::StackTrace => AyaMap::StackTraceMap(map_data),
        MapType::XskMap => AyaMap::XskMap(map_data),
        _ => AyaMap::Unsupported(map_data),
    })
}

fn open_libbpf_object(elf_bytes: &[u8], context: &str) -> Result<*mut bpf_object, LoadError> {
    let api = libbpf_api()?;

    // SAFETY: `elf_bytes` stays owned by the returned handle for the lifetime of `object`.
    let object = unsafe {
        (api.bpf_object_open_mem)(elf_bytes.as_ptr().cast(), elf_bytes.len(), ptr::null())
    };
    let open_err = unsafe { (api.libbpf_get_error)(object.cast()) };
    if open_err != 0 {
        return Err(pointer_error_message(context, open_err));
    }
    if object.is_null() {
        return Err(LoadError::Load(format!(
            "libbpf returned a null object while opening {context}"
        )));
    }

    Ok(object)
}

fn load_libbpf_object(object: *mut bpf_object, context: &str) -> Result<(), LoadError> {
    let api = libbpf_api()?;

    // SAFETY: `object` is a valid libbpf object returned by `bpf_object__open_mem`.
    let load_rc = unsafe { (api.bpf_object_load)(object) };
    if load_rc != 0 {
        // SAFETY: `object` is valid and should be closed on error.
        unsafe { (api.bpf_object_close)(object) };
        return Err(negative_rc_message(context, load_rc));
    }

    Ok(())
}

fn close_libbpf_object(object: *mut bpf_object) {
    if object.is_null() {
        return;
    }

    if let Ok(api) = libbpf_api() {
        // SAFETY: `object` is owned by the caller and is being closed at most once.
        unsafe { (api.bpf_object_close)(object) };
    }
}

fn destroy_libbpf_link(link: *mut bpf_link) {
    if link.is_null() {
        return;
    }

    if let Ok(api) = libbpf_api() {
        // SAFETY: `link` is owned by the caller and is being destroyed at most once.
        unsafe {
            (api.bpf_link_destroy)(link);
        }
    }
}

fn export_maps_from_object(object: *mut bpf_object) -> Result<HashMap<String, AyaMap>, LoadError> {
    if object.is_null() {
        return Err(LoadError::Load(
            "cannot export maps from a closed libbpf object".to_string(),
        ));
    }

    let api = libbpf_api()?;
    let mut maps = HashMap::new();
    let mut previous_map: *mut bpf_map = ptr::null_mut();

    loop {
        // SAFETY: `object` is a loaded libbpf object, and `previous_map` is either null
        // or a map pointer returned by the prior iteration.
        let map = unsafe { (api.bpf_object_next_map)(object.cast_const(), previous_map) };
        if map.is_null() {
            break;
        }

        // SAFETY: `map` is a live libbpf map pointer.
        let name_ptr = unsafe { (api.bpf_map_name)(map) };
        if name_ptr.is_null() {
            return Err(LoadError::Load(
                "libbpf returned a map with a null name".to_string(),
            ));
        }
        // SAFETY: libbpf map names are valid NUL-terminated strings for live maps.
        let map_name = unsafe { CStr::from_ptr(name_ptr) }
            .to_string_lossy()
            .into_owned();

        // SAFETY: `map` is a live libbpf map pointer.
        let fd = unsafe { (api.bpf_map_fd)(map) };
        let owned_fd = duplicate_libbpf_map_fd(&map_name, fd)?;
        let map_data = MapData::from_fd(owned_fd).map_err(|error| {
            LoadError::Load(format!(
                "Failed to import libbpf map '{map_name}' into Aya map data: {error}"
            ))
        })?;
        let aya_map = aya_map_from_map_data(&map_name, map_data)?;

        if maps.insert(map_name.clone(), aya_map).is_some() {
            return Err(LoadError::Load(format!(
                "libbpf object contains duplicate map name '{map_name}'"
            )));
        }

        previous_map = map;
    }

    Ok(maps)
}

pub struct LibbpfStructOpsHandle {
    _elf_bytes: Vec<u8>,
    object: *mut bpf_object,
    link: *mut bpf_link,
}

// SAFETY: The handle owns process-local libbpf pointers and is only accessed
// through the loader's mutex-protected probe table. We never share interior
// references to the raw pointers across threads.
unsafe impl Send for LibbpfStructOpsHandle {}

impl LibbpfStructOpsHandle {
    pub fn load_and_attach(elf_bytes: Vec<u8>, map_name: &str) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let map_name = CString::new(map_name)
            .map_err(|_| LoadError::Load(format!("invalid struct_ops map name '{map_name}'")))?;

        let object =
            open_libbpf_object(&elf_bytes, "Failed to open struct_ops object with libbpf")?;
        load_libbpf_object(object, "Failed to load struct_ops object")?;

        // SAFETY: `object` is loaded and `map_name` is a valid C string.
        let map = unsafe { (api.bpf_object_find_map_by_name)(object, map_name.as_ptr()) };
        if map.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(format!(
                "Failed to find struct_ops map '{name}' in loaded object",
                name = map_name.to_string_lossy()
            )));
        }

        // SAFETY: `map` points to the struct_ops map discovered in the loaded object.
        let link = unsafe { (api.bpf_map_attach_struct_ops)(map) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(
                "Failed to attach struct_ops object",
                attach_err,
            ));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(
                "libbpf returned a null struct_ops link".to_string(),
            ));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn export_maps(&self) -> Result<HashMap<String, AyaMap>, LoadError> {
        export_maps_from_object(self.object)
    }
}

pub struct LibbpfProgramHandle {
    _elf_bytes: Vec<u8>,
    object: *mut bpf_object,
    link: *mut bpf_link,
}

// SAFETY: The handle owns process-local libbpf pointers and is only accessed
// through the loader's mutex-protected probe table. We never share interior
// references to the raw pointers across threads.
unsafe impl Send for LibbpfProgramHandle {}

impl LibbpfProgramHandle {
    fn loaded_program(
        object: *mut bpf_object,
        program_name: &CString,
        program_label: &str,
    ) -> Result<*mut bpf_program, LoadError> {
        let api = libbpf_api()?;

        // SAFETY: `object` is loaded and `program_name` is a valid C string.
        let program =
            unsafe { (api.bpf_object_find_program_by_name)(object, program_name.as_ptr()) };
        if program.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(format!(
                "Failed to find {program_label} program '{name}' in loaded object",
                name = program_name.to_string_lossy()
            )));
        }

        Ok(program)
    }

    pub fn load_and_attach_raw_tracepoint(
        elf_bytes: Vec<u8>,
        program_name: &str,
        tracepoint_name: &str,
    ) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let program_name = CString::new(program_name).map_err(|_| {
            LoadError::Load(format!("invalid libbpf program name '{program_name}'"))
        })?;
        let tracepoint_name = CString::new(tracepoint_name).map_err(|_| {
            LoadError::Load(format!("invalid raw tracepoint name '{tracepoint_name}'"))
        })?;

        let object = open_libbpf_object(
            &elf_bytes,
            "Failed to open raw_tracepoint.w object with libbpf",
        )?;
        load_libbpf_object(object, "Failed to load raw_tracepoint.w object")?;

        let program = Self::loaded_program(object, &program_name, "raw_tracepoint.w")?;

        // SAFETY: `program` is loaded by libbpf and `tracepoint_name` names the raw tracepoint.
        let link =
            unsafe { (api.bpf_program_attach_raw_tracepoint)(program, tracepoint_name.as_ptr()) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(
                "Failed to attach raw_tracepoint.w program",
                attach_err,
            ));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(
                "libbpf returned a null raw_tracepoint.w link".to_string(),
            ));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn load_and_attach_trace(
        elf_bytes: Vec<u8>,
        program_name: &str,
        program_label: &str,
    ) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let program_name = CString::new(program_name).map_err(|_| {
            LoadError::Load(format!("invalid libbpf program name '{program_name}'"))
        })?;
        let open_context = format!("Failed to open {program_label} object with libbpf");
        let load_context = format!("Failed to load {program_label} object");
        let attach_context = format!("Failed to attach {program_label} program");

        let object = open_libbpf_object(&elf_bytes, &open_context)?;
        load_libbpf_object(object, &load_context)?;
        let program = Self::loaded_program(object, &program_name, program_label)?;

        // SAFETY: `program` is loaded by libbpf with section-preserved tracing metadata.
        let link = unsafe { (api.bpf_program_attach_trace)(program) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(&attach_context, attach_err));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(format!(
                "libbpf returned a null {program_label} link"
            )));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn load_and_attach_cgroup(
        elf_bytes: Vec<u8>,
        program_name: &str,
        cgroup_fd: c_int,
        program_label: &str,
    ) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let attach_cgroup = api.bpf_program_attach_cgroup.ok_or_else(|| {
            LoadError::Load(format!(
                "libbpf does not provide bpf_program__attach_cgroup; {program_label} live attach requires libbpf cgroup attach support"
            ))
        })?;
        let program_name = CString::new(program_name).map_err(|_| {
            LoadError::Load(format!("invalid libbpf program name '{program_name}'"))
        })?;
        let open_context = format!("Failed to open {program_label} object with libbpf");
        let load_context = format!("Failed to load {program_label} object");
        let attach_context = format!("Failed to attach {program_label} program");

        let object = open_libbpf_object(&elf_bytes, &open_context)?;
        load_libbpf_object(object, &load_context)?;
        let program = Self::loaded_program(object, &program_name, program_label)?;

        // SAFETY: `program` is loaded by libbpf and `cgroup_fd` references an open cgroup dir.
        let link = unsafe { attach_cgroup(program, cgroup_fd) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(&attach_context, attach_err));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(format!(
                "libbpf returned a null {program_label} link"
            )));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn load_and_attach_netfilter(
        elf_bytes: Vec<u8>,
        program_name: &str,
        opts: BpfNetfilterOpts,
    ) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let attach_netfilter = api.bpf_program_attach_netfilter.ok_or_else(|| {
            LoadError::Load(
                "libbpf does not provide bpf_program__attach_netfilter; netfilter live attach requires libbpf 1.3 or newer".to_string(),
            )
        })?;
        let program_name = CString::new(program_name).map_err(|_| {
            LoadError::Load(format!("invalid libbpf program name '{program_name}'"))
        })?;

        let object = open_libbpf_object(&elf_bytes, "Failed to open netfilter object with libbpf")?;
        load_libbpf_object(object, "Failed to load netfilter object")?;
        let program = Self::loaded_program(object, &program_name, "netfilter")?;

        // SAFETY: `program` is loaded by libbpf and `opts` follows libbpf's netfilter ABI.
        let link = unsafe { attach_netfilter(program, &opts) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(
                "Failed to attach netfilter program",
                attach_err,
            ));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(
                "libbpf returned a null netfilter link".to_string(),
            ));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn load_and_attach_netkit(
        elf_bytes: Vec<u8>,
        program_name: &str,
        ifindex: c_int,
        opts: BpfNetkitOpts,
    ) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let attach_netkit = api.bpf_program_attach_netkit.ok_or_else(|| {
            LoadError::Load(
                "libbpf does not provide bpf_program__attach_netkit; netkit live attach requires libbpf 1.3 or newer".to_string(),
            )
        })?;
        let program_name = CString::new(program_name).map_err(|_| {
            LoadError::Load(format!("invalid libbpf program name '{program_name}'"))
        })?;

        let object = open_libbpf_object(&elf_bytes, "Failed to open netkit object with libbpf")?;
        load_libbpf_object(object, "Failed to load netkit object")?;
        let program = Self::loaded_program(object, &program_name, "netkit")?;

        // SAFETY: `program` is loaded by libbpf and `opts` follows libbpf's netkit ABI.
        let link = unsafe { attach_netkit(program, ifindex, &opts) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(
                "Failed to attach netkit program",
                attach_err,
            ));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(
                "libbpf returned a null netkit link".to_string(),
            ));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn load_and_attach_netns(
        elf_bytes: Vec<u8>,
        program_name: &str,
        netns_fd: c_int,
        program_label: &str,
    ) -> Result<Self, LoadError> {
        let api = libbpf_api()?;
        let attach_netns = api.bpf_program_attach_netns.ok_or_else(|| {
            LoadError::Load(format!(
                "libbpf does not provide bpf_program__attach_netns; {program_label} live attach requires a newer libbpf"
            ))
        })?;
        let program_name = CString::new(program_name).map_err(|_| {
            LoadError::Load(format!("invalid libbpf program name '{program_name}'"))
        })?;
        let open_context = format!("Failed to open {program_label} object with libbpf");
        let load_context = format!("Failed to load {program_label} object");
        let attach_context = format!("Failed to attach {program_label} program");

        let object = open_libbpf_object(&elf_bytes, &open_context)?;
        load_libbpf_object(object, &load_context)?;
        let program = Self::loaded_program(object, &program_name, program_label)?;

        // SAFETY: `program` is loaded by libbpf and `netns_fd` references an open netns file.
        let link = unsafe { attach_netns(program, netns_fd) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            close_libbpf_object(object);
            return Err(pointer_error_message(&attach_context, attach_err));
        }
        if link.is_null() {
            close_libbpf_object(object);
            return Err(LoadError::Load(format!(
                "libbpf returned a null {program_label} link"
            )));
        }

        Ok(Self {
            _elf_bytes: elf_bytes,
            object,
            link,
        })
    }

    pub fn export_maps(&self) -> Result<HashMap<String, AyaMap>, LoadError> {
        export_maps_from_object(self.object)
    }
}

impl Drop for LibbpfStructOpsHandle {
    fn drop(&mut self) {
        if !self.link.is_null() {
            destroy_libbpf_link(self.link);
            self.link = ptr::null_mut();
        }

        if !self.object.is_null() {
            close_libbpf_object(self.object);
            self.object = ptr::null_mut();
        }
    }
}

impl Drop for LibbpfProgramHandle {
    fn drop(&mut self) {
        if !self.link.is_null() {
            destroy_libbpf_link(self.link);
            self.link = ptr::null_mut();
        }

        if !self.object.is_null() {
            close_libbpf_object(self.object);
            self.object = ptr::null_mut();
        }
    }
}
