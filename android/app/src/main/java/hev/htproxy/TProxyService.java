package hev.htproxy;

/**
 * JNI binding for libhev-socks5-tunnel.so (hev-socks5-tunnel).
 *
 * src/hev-jni.c registers its natives to this exact class when the library is
 * loaded (JNI_OnLoad -> FindClass("hev/htproxy/TProxyService") + RegisterNatives).
 * The class/package must not be renamed unless the native library is rebuilt
 * with other PKGNAME/CLSNAME values (see Application.mk).
 */
public final class TProxyService {
    private TProxyService() {
    }

    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    public static native boolean TProxyStartService(String config_path, int fd);

    public static native boolean TProxyStopService();

    public static native boolean TProxyIsRunning();

    public static native long[] TProxyGetStats();
}
