use super::*;
use libc::{c_char, c_int, c_long, c_void};
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
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
struct bpf_link {
    _private: [u8; 0],
}

type BpfObjectOpenMemFn =
    unsafe extern "C" fn(*const c_void, usize, *const c_void) -> *mut bpf_object;
type BpfObjectLoadFn = unsafe extern "C" fn(*mut bpf_object) -> c_int;
type BpfObjectCloseFn = unsafe extern "C" fn(*mut bpf_object);
type BpfObjectFindMapByNameFn =
    unsafe extern "C" fn(*const bpf_object, *const c_char) -> *mut bpf_map;
type BpfMapAttachStructOpsFn = unsafe extern "C" fn(*const bpf_map) -> *mut bpf_link;
type BpfLinkDestroyFn = unsafe extern "C" fn(*mut bpf_link) -> c_int;
type LibbpfGetErrorFn = unsafe extern "C" fn(*const c_void) -> c_long;

struct LibbpfApi {
    _handle: *mut c_void,
    bpf_object_open_mem: BpfObjectOpenMemFn,
    bpf_object_load: BpfObjectLoadFn,
    bpf_object_close: BpfObjectCloseFn,
    bpf_object_find_map_by_name: BpfObjectFindMapByNameFn,
    bpf_map_attach_struct_ops: BpfMapAttachStructOpsFn,
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
                bpf_object_find_map_by_name: Self::load_symbol(
                    handle,
                    b"bpf_object__find_map_by_name\0",
                )?,
                bpf_map_attach_struct_ops: Self::load_symbol(
                    handle,
                    b"bpf_map__attach_struct_ops\0",
                )?,
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

        // SAFETY: `elf_bytes` stays owned by the returned handle for the lifetime of `object`.
        let object = unsafe {
            (api.bpf_object_open_mem)(elf_bytes.as_ptr().cast(), elf_bytes.len(), ptr::null())
        };
        let open_err = unsafe { (api.libbpf_get_error)(object.cast()) };
        if open_err != 0 {
            return Err(pointer_error_message(
                "Failed to open struct_ops object with libbpf",
                open_err,
            ));
        }
        if object.is_null() {
            return Err(LoadError::Load(
                "libbpf returned a null struct_ops object".to_string(),
            ));
        }

        // SAFETY: `object` is a valid libbpf object returned by `bpf_object__open_mem`.
        let load_rc = unsafe { (api.bpf_object_load)(object) };
        if load_rc != 0 {
            // SAFETY: `object` is valid and should be closed on error.
            unsafe { (api.bpf_object_close)(object) };
            return Err(negative_rc_message(
                "Failed to load struct_ops object",
                load_rc,
            ));
        }

        // SAFETY: `object` is loaded and `map_name` is a valid C string.
        let map = unsafe { (api.bpf_object_find_map_by_name)(object, map_name.as_ptr()) };
        if map.is_null() {
            // SAFETY: `object` is valid and should be closed on error.
            unsafe { (api.bpf_object_close)(object) };
            return Err(LoadError::Load(format!(
                "Failed to find struct_ops map '{name}' in loaded object",
                name = map_name.to_string_lossy()
            )));
        }

        // SAFETY: `map` points to the struct_ops map discovered in the loaded object.
        let link = unsafe { (api.bpf_map_attach_struct_ops)(map) };
        let attach_err = unsafe { (api.libbpf_get_error)(link.cast()) };
        if attach_err != 0 {
            // SAFETY: `object` is valid and should be closed on error.
            unsafe { (api.bpf_object_close)(object) };
            return Err(pointer_error_message(
                "Failed to attach struct_ops object",
                attach_err,
            ));
        }
        if link.is_null() {
            // SAFETY: `object` is valid and should be closed on error.
            unsafe { (api.bpf_object_close)(object) };
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
}

impl Drop for LibbpfStructOpsHandle {
    fn drop(&mut self) {
        let Ok(api) = libbpf_api() else {
            return;
        };

        if !self.link.is_null() {
            // SAFETY: `link` is owned by this handle and destroyed at most once.
            unsafe {
                (api.bpf_link_destroy)(self.link);
            }
            self.link = ptr::null_mut();
        }

        if !self.object.is_null() {
            // SAFETY: `object` is owned by this handle and closed at most once.
            unsafe {
                (api.bpf_object_close)(self.object);
            }
            self.object = ptr::null_mut();
        }
    }
}
