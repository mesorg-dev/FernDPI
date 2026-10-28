package com.ferndpi.app.ui

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.ferndpi.app.ui.main.MainScreen
import com.ferndpi.app.ui.settings.AppsScreen
import com.ferndpi.app.ui.settings.SettingsScreen

@Composable
fun FernDPIApp(viewModel: AppViewModel) {
    val navController = rememberNavController()
    NavHost(navController = navController, startDestination = "main") {
        composable("main") {
            MainScreen(
                viewModel = viewModel,
                onOpenSettings = { navController.navigate("settings") },
            )
        }
        composable("settings") {
            SettingsScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() },
                onOpenApps = { navController.navigate("apps") },
            )
        }
        composable("apps") {
            AppsScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() },
            )
        }
    }
}
