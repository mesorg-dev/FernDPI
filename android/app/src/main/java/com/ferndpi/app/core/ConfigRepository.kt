package com.ferndpi.app.core

import android.content.Context
import android.net.Uri
import java.io.File

data class ConfigEntry(
    val id: String,
    val label: String,
    val path: String?,
)

class ConfigRepository(private val context: Context) {

    private val configsDir: File get() = File(context.filesDir, "configs")
    private val importedDir: File get() = File(context.filesDir, "imported")

    fun loadAll(): List<ConfigEntry> {
        val presets = ensurePresets()
        val flowseal = ensureFlowseal()
        val imported = importedDir.listFiles { f -> f.isFile && f.extension == "toml" }
            .orEmpty()
            .sortedBy { it.name.lowercase() }
            .map { ConfigEntry("imported:${it.name}", it.name.removeSuffix(".toml"), it.absolutePath) }
        return presets + flowseal + imported
    }

    fun pathFor(id: String, configs: List<ConfigEntry>): String? =
        configs.firstOrNull { it.id == id }?.path

    fun importFromUri(uri: Uri, label: String): ConfigEntry? {
        val safeName = label.replace(Regex("[^A-Za-z0-9._-]"), "_").ifEmpty { "imported.toml" }
        val name = if (safeName.endsWith(".toml")) safeName else "$safeName.toml"
        val target = File(importedDir, name)
        return runCatching {
            importedDir.mkdirs()
            context.contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { input.copyTo(it) }
            } ?: return null
            if (target.length() == 0L) {
                target.delete()
                return null
            }
            ConfigEntry("imported:$name", name.removeSuffix(".toml"), target.absolutePath)
        }.getOrNull()
    }

    private fun ensureFlowseal(): List<ConfigEntry> {
        val bats = context.assets.list(FLOWSEAL_ASSET_DIR)
            .orEmpty()
            .filter { it.endsWith(".bat", ignoreCase = true) }
        if (bats.isEmpty()) return emptyList()
        val dest = File(context.filesDir, "flowseal")
        runCatching { copyAssetDir(FLOWSEAL_ASSET_DIR, dest) }
        return bats.sorted().map { name ->
            ConfigEntry(
                id = "flowseal:$name",
                label = "Flowseal: ${name.removeSuffix(".bat")}",
                path = File(dest, name).absolutePath,
            )
        }
    }

    private fun copyAssetDir(assetPath: String, destDir: File) {
        destDir.mkdirs()
        val children = context.assets.list(assetPath).orEmpty()
        for (name in children) {
            val childAsset = "$assetPath/$name"
            val target = File(destDir, name)
            if (context.assets.list(childAsset).orEmpty().isNotEmpty()) {
                copyAssetDir(childAsset, target)
            } else {
                context.assets.open(childAsset).use { input ->
                    target.outputStream().use { input.copyTo(it) }
                }
            }
        }
    }

    private fun ensurePresets(): List<ConfigEntry> {
        val names = context.assets.list("configs").orEmpty().filter { it.endsWith(".toml") }
        configsDir.mkdirs()
        val entries = mutableListOf<ConfigEntry>()
        for (name in names.sorted()) {
            val target = File(configsDir, name)
            runCatching {
                context.assets.open("configs/$name").use { input ->
                    target.outputStream().use { input.copyTo(it) }
                }
            }
            if (target.isFile) {
                entries += ConfigEntry(
                    id = "preset:${name.removeSuffix(".toml")}",
                    label = name.removeSuffix(".toml").replace('_', ' '),
                    path = target.absolutePath,
                )
            }
        }
        return entries
    }

    companion object {
        const val CUSTOM_ID = "custom"
        private const val FLOWSEAL_ASSET_DIR = "flowseal"
    }
}
