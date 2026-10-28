//! Android JNI bridge.
//!
//! Runs the FernDPI core in-process (a cdylib loaded by the app) so that every
//! outgoing socket can be passed through `VpnService.protect()` — without it
//! our own traffic would loop back into the tun.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use ferndpi::config::{Cli, Config};
use ferndpi::core::Core;
use clap::Parser;
use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};
use tokio::net::TcpListener;
use tracing::{error, info};

static VM: OnceLock<JavaVM> = OnceLock::new();
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
static SERVICE: Mutex<Option<GlobalRef>> = Mutex::new(None);
static LOG_SINK: Mutex<Option<GlobalRef>> = Mutex::new(None);
static RUNNING: AtomicBool = AtomicBool::new(false);

fn android_protect(fd: i32) -> bool {
    let Some(vm) = VM.get() else { return false };
    let Ok(mut env) = vm.attach_current_thread() else {
        return false;
    };
    let guard = SERVICE.lock().unwrap();
    let Some(service) = guard.as_ref() else {
        return false;
    };
    let res = env.call_method(service.as_obj(), "protect", "(I)Z", &[jni::objects::JValue::Int(fd)]);
    match res {
        Ok(v) => v.z().unwrap_or(false),
        Err(_) => false,
    }
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("ferndpi={level},ferndpi_android={level},{level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .try_init();
}

/// Log line → stdout (logcat) + optional Java sink (app log view).
fn writer() -> impl std::io::Write + Send + Sync + 'static {
    TracingWriter
}

struct TracingWriter;

impl std::io::Write for TracingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(text) = std::str::from_utf8(buf) {
            let line = text.trim_end();
            if line.is_empty() {
                return Ok(buf.len());
            }
            let _ = std::io::stdout().write_all(buf);
            emit_to_sink(line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        Ok(())
    }
}

fn emit_to_sink(line: &str) {
    let Some(vm) = VM.get() else { return };
    let Ok(mut env) = vm.attach_current_thread() else {
        return;
    };
    let guard = LOG_SINK.lock().unwrap();
    let Some(sink) = guard.as_ref() else { return };
    let Ok(jline) = env.new_string(line) else { return };
    let _ = env.call_method(sink.as_obj(), "onLog", "(Ljava/lang/String;)V", &[(&jline).into()]);
}

fn stop_inner() {
    if let Some(h) = HANDLE.lock().unwrap().take() {
        h.abort();
    }
    RUNNING.store(false, Ordering::Release);
}

/// `start(argsJson, vpnService)` — argsJson is a JSON array of CLI arguments.
#[no_mangle]
pub extern "system" fn Java_com_fernndpi_app_core_NativeCore_start0(
    mut env: JNIEnv,
    _class: JClass,
    args_json: JString,
    service: JObject,
) -> jboolean {
    let vm = match env.get_java_vm() {
        Ok(v) => v,
        Err(e) => {
            error!("get_java_vm: {e}");
            return JNI_FALSE;
        }
    };
    let _ = VM.set(vm);

    let args: Vec<String> = match env.get_string(&args_json) {
        Ok(s) => {
            let s: String = s.into();
            serde_json::from_str(&s).unwrap_or_default()
        }
        Err(_) => Vec::new(),
    };

    // Keep a global ref so the protect() callback survives Java stack frames.
    *SERVICE.lock().unwrap() = if service.is_null() {
        None
    } else {
        env.new_global_ref(&service).ok()
    };

    ferndpi::netguard::set_protect_hook(android_protect);

    let argv = std::iter::once("ferndpi".to_string()).chain(args);
    let cli = match Cli::try_parse_from(argv) {
        Ok(c) => c,
        Err(e) => {
            error!("cli: {e}");
            return JNI_FALSE;
        }
    };
    let cfg = match Config::from_cli(&cli) {
        Ok(c) => c,
        Err(e) => {
            error!("config: {e}");
            return JNI_FALSE;
        }
    };
    init_tracing(cfg.verbose);

    let rt = RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("tokio runtime"));
    stop_inner();

    let listen = cfg.listen;
    let listener = match rt.block_on(TcpListener::bind(listen)) {
        Ok(l) => l,
        Err(e) => {
            error!("bind {listen}: {e}");
            return JNI_FALSE;
        }
    };
    let core = Core::new(cfg);
    let handle = rt.spawn(async move {
        if let Err(e) = core.serve(listener).await {
            error!("serve: {e:#}");
        }
    });
    *HANDLE.lock().unwrap() = Some(handle);
    RUNNING.store(true, Ordering::Release);
    info!("core started in-process on {listen}");
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_com_fernndpi_app_core_NativeCore_stop0(
    _env: JNIEnv,
    _class: JClass,
) {
    stop_inner();
    *SERVICE.lock().unwrap() = None;
    info!("core stopped");
}

#[no_mangle]
pub extern "system" fn Java_com_fernndpi_app_core_NativeCore_isRunning0(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if RUNNING.load(Ordering::Acquire) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// `setLogSink(sink)` — sink is a `NativeCore.LogSink` lambda or null.
#[no_mangle]
pub extern "system" fn Java_com_fernndpi_app_core_NativeCore_setLogSink0(
    env: JNIEnv,
    _class: JClass,
    sink: JObject,
) {
    *LOG_SINK.lock().unwrap() = if sink.is_null() {
        None
    } else {
        env.new_global_ref(&sink).ok()
    };
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: JavaVM, _reserved: *mut std::ffi::c_void) -> jni::sys::jint {
    JNI_VERSION_1_6 as jni::sys::jint
}
