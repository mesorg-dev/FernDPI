package com.ferndpi.app.ui.main

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenu
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.ferndpi.app.R
import com.ferndpi.app.core.ConfigEntry
import com.ferndpi.app.core.ConfigRepository
import com.ferndpi.app.core.CoreState
import com.ferndpi.app.ui.AppViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: AppViewModel,
    onOpenSettings: () -> Unit,
) {
    val state by viewModel.coreState.collectAsState()
    val log by viewModel.coreLog.collectAsState()
    val configs by viewModel.configs.collectAsState()
    val importFailed by viewModel.importFailed.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    val importFailedText = stringResource(R.string.config_import_failed)
    LaunchedEffect(importFailed) {
        if (importFailed) {
            snackbarHostState.showSnackbar(importFailedText)
            viewModel.consumeImportFailed()
        }
    }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { viewModel.importConfig(it) } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.main_title)) },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(
                            imageVector = Icons.Filled.Settings,
                            contentDescription = stringResource(R.string.settings),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            StatusCard(
                state = state,
                proxyAddress = stringResource(R.string.proxy_address, "127.0.0.1:${settings.port}"),
                onToggle = {
                    when (state) {
                        is CoreState.Stopped, is CoreState.Error -> viewModel.connect()
                        else -> viewModel.disconnect()
                    }
                },
            )

            ConfigCard(
                configs = configs,
                selectedId = settings.configId,
                onSelect = viewModel::selectConfig,
                onImport = { importLauncher.launch(arrayOf("*/*")) },
            )

            LogCard(log = log)
        }
    }
}

@Composable
private fun StatusCard(
    state: CoreState,
    proxyAddress: String,
    onToggle: () -> Unit,
) {
    val running = state is CoreState.Running
    val starting = state is CoreState.Starting
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = when (state) {
                    is CoreState.Running -> stringResource(R.string.status_connected)
                    is CoreState.Starting -> stringResource(R.string.status_connecting)
                    is CoreState.Error -> stringResource(R.string.status_error)
                    is CoreState.Stopped -> stringResource(R.string.status_disconnected)
                },
                style = MaterialTheme.typography.headlineMedium,
                color = when {
                    running -> MaterialTheme.colorScheme.primary
                    state is CoreState.Error -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = if (running || starting) proxyAddress else " ",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state is CoreState.Error) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = state.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                )
            }
            Spacer(Modifier.height(20.dp))
            Button(
                onClick = onToggle,
                enabled = !starting,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = if (running) {
                    ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    )
                } else {
                    ButtonDefaults.buttonColors()
                },
            ) {
                Text(
                    text = stringResource(if (running) R.string.disconnect else R.string.connect),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConfigCard(
    configs: List<ConfigEntry>,
    selectedId: String,
    onSelect: (String) -> Unit,
    onImport: () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val selected = configs.firstOrNull { it.id == selectedId }
    val customLabel = stringResource(R.string.config_custom)

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.config_section),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(12.dp))
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
                        text = selected?.label ?: customLabel,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                    )
                    Icon(
                        imageVector = Icons.Filled.ArrowDropDown,
                        contentDescription = null,
                    )
                }
                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false },
                ) {
                    DropdownMenuItem(
                        text = { Text(customLabel) },
                        onClick = {
                            onSelect(ConfigRepository.CUSTOM_ID)
                            expanded = false
                        },
                    )
                    configs.filter { it.id != ConfigRepository.CUSTOM_ID }.forEach { entry ->
                        DropdownMenuItem(
                            text = { Text(entry.label) },
                            onClick = {
                                onSelect(entry.id)
                                expanded = false
                            },
                        )
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onImport,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.config_import))
            }
        }
    }
}

@Composable
private fun LogCard(log: List<String>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.log_section),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(8.dp))
            if (log.isEmpty()) {
                Text(
                    text = stringResource(R.string.log_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                LazyColumn(
                    modifier = Modifier.heightIn(max = 200.dp),
                    reverseLayout = true,
                ) {
                    items(log.reversed()) { line ->
                        Text(
                            text = line,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 1.dp),
                        )
                    }
                }
            }
        }
    }
}
