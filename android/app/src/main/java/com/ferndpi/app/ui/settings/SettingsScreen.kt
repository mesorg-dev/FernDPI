package com.ferndpi.app.ui.settings

import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.os.LocaleListCompat
import com.ferndpi.app.R
import com.ferndpi.app.core.ThemeMode
import com.ferndpi.app.ui.AppViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: AppViewModel,
    onBack: () -> Unit,
) {
    val settings by viewModel.settings.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            SectionHeader(stringResource(R.string.appearance_section))

            Text(
                text = stringResource(R.string.theme_mode),
                style = MaterialTheme.typography.bodyLarge,
            )
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                ThemeMode.entries.forEachIndexed { index, mode ->
                    SegmentedButton(
                        selected = settings.themeMode == mode,
                        onClick = { viewModel.updateSettings { it.copy(themeMode = mode) } },
                        shape = SegmentedButtonDefaults.itemShape(index, ThemeMode.entries.size),
                    ) {
                        Text(
                            text = stringResource(
                                when (mode) {
                                    ThemeMode.SYSTEM -> R.string.theme_system
                                    ThemeMode.LIGHT -> R.string.theme_light
                                    ThemeMode.DARK -> R.string.theme_dark
                                }
                            ),
                            maxLines = 1,
                        )
                    }
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                SwitchRow(
                    label = stringResource(R.string.dynamic_colors),
                    checked = settings.dynamicColor,
                    onCheckedChange = { value ->
                        viewModel.updateSettings { it.copy(dynamicColor = value) }
                    },
                )
            }

            Divider(modifier = Modifier.padding(vertical = 8.dp))
            SectionHeader(stringResource(R.string.core_section))

            NumberField(
                label = stringResource(R.string.socks_port),
                value = settings.port,
                range = 1024..65535,
                onChange = { viewModel.updateSettings { s -> s.copy(port = it) } },
            )

            val strategies = listOf("none", "split", "multisplit", "frag", "http")
            SettingsDropdown(
                label = stringResource(R.string.strategy),
                value = settings.strategy,
                entries = strategies.map { it to strategyLabel(it) },
                onSelect = { viewModel.updateSettings { s -> s.copy(strategy = it) } },
            )

            if (settings.strategy in listOf("split", "multisplit", "frag")) {
                val positions = listOf("mid", "midsld", "end")
                SettingsDropdown(
                    label = stringResource(R.string.split_pos),
                    value = settings.splitPos,
                    entries = positions.map { it to splitPosLabel(it) },
                    onSelect = { viewModel.updateSettings { s -> s.copy(splitPos = it) } },
                )
            }

            if (settings.strategy == "frag") {
                NumberField(
                    label = stringResource(R.string.frag_size),
                    value = settings.fragSize,
                    range = 16..1500,
                    onChange = { viewModel.updateSettings { s -> s.copy(fragSize = it) } },
                )
            }

            if (settings.strategy != "none") {
                NumberField(
                    label = stringResource(R.string.delay_ms),
                    value = settings.delayMs,
                    range = 0..5000,
                    onChange = { viewModel.updateSettings { s -> s.copy(delayMs = it) } },
                )
            }

            SettingsDropdown(
                label = stringResource(R.string.language),
                value = settings.lang,
                entries = listOf(
                    "system" to stringResource(R.string.language_system),
                    "en" to "English",
                    "ru" to "Русский",
                ),
                onSelect = { lang ->
                    viewModel.updateSettings { s -> s.copy(lang = lang) }
                    AppCompatDelegate.setApplicationLocales(
                        if (lang == "system") {
                            LocaleListCompat.getEmptyLocaleList()
                        } else {
                            LocaleListCompat.forLanguageTags(lang)
                        }
                    )
                },
            )

            Divider(modifier = Modifier.padding(vertical = 8.dp))
            SectionHeader(stringResource(R.string.behavior_section))

            SwitchRow(
                label = stringResource(R.string.autostart),
                checked = settings.autoStart,
                onCheckedChange = { value ->
                    viewModel.updateSettings { it.copy(autoStart = value) }
                },
            )
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp),
    )
}

@Composable
private fun SwitchRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun NumberField(
    label: String,
    value: Int,
    range: IntRange,
    onChange: (Int) -> Unit,
) {
    OutlinedTextField(
        value = value.toString(),
        onValueChange = { raw ->
            val digits = raw.filter { it.isDigit() }
            val parsed = digits.toIntOrNull() ?: return@OutlinedTextField
            onChange(parsed.coerceIn(range.first, range.last))
        },
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsDropdown(
    label: String,
    value: String,
    entries: List<Pair<String, String>>,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val currentLabel = entries.firstOrNull { it.first == value }?.second ?: value

    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(top = 4.dp),
        )
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
        ) {
            OutlinedButton(
                onClick = { expanded = true },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(),
            ) {
                Text(
                    text = currentLabel,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                )
                Icon(
                    imageVector = Icons.Filled.ArrowDropDown,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                )
            }
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                entries.forEach { (key, text) ->
                    DropdownMenuItem(
                        text = { Text(text) },
                        onClick = {
                            onSelect(key)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun strategyLabel(id: String): String = stringResource(
    when (id) {
        "none" -> R.string.strategy_none
        "split" -> R.string.strategy_split
        "multisplit" -> R.string.strategy_multisplit
        "frag" -> R.string.strategy_frag
        else -> R.string.strategy_http
    }
)

@Composable
private fun splitPosLabel(id: String): String = stringResource(
    when (id) {
        "midsld" -> R.string.split_pos_midsld
        "end" -> R.string.split_pos_end
        else -> R.string.split_pos_mid
    }
)
