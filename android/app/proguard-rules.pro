# JNI: symbols resolved by name (Java_com_fernndpi_app_core_NativeCore_*) and
# by RegisterNatives (hev.htproxy.TProxyService) — must not be obfuscated.
-keep class com.ferndpi.app.core.NativeCore { *; }
-keep class com.ferndpi.app.core.NativeCore$LogSink { *; }
-keep class hev.htproxy.TProxyService { *; }
