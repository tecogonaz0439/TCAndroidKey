// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.MenuOpen
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Menu
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.PermanentDrawerSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import net.tecogonaz.tcandroidkey.ui.document.DocumentScreen
import net.tecogonaz.tcandroidkey.ui.document.LegalDocument
import kotlinx.coroutines.launch
import net.tecogonaz.tcandroidkey.R
import net.tecogonaz.tcandroidkey.ui.about.AboutScreen
import net.tecogonaz.tcandroidkey.ui.authenticator.AuthenticatorScreen
import net.tecogonaz.tcandroidkey.ui.common.AutoResizingSingleLineText
import net.tecogonaz.tcandroidkey.ui.common.mouseDragScroll
import net.tecogonaz.tcandroidkey.ui.credentials.CredentialsScreen
import net.tecogonaz.tcandroidkey.ui.log.EventLogScreen
import net.tecogonaz.tcandroidkey.ui.settings.SettingsScreen

/** 画面ルート。 */
object Routes {
    const val AUTHENTICATOR = "authenticator"
    const val CREDENTIALS = "credentials"
    const val LOG = "log"
    const val SETTINGS = "settings"
    const val ABOUT = "about"

    /** 利用規約・セキュリティポリシー (「このアプリについて」から開く)。 */
    const val DOCUMENT = "document/{id}"
    fun document(id: String): String = "document/$id"
}

/** Activity が提供する UI 操作 (本人確認ダイアログ、システム設定画面の起動など)。 */
data class UiActions(
    /** 本人確認を行い、成功したら認証の受付を開始する。 */
    val armWithVerification: () -> Unit,
    /** 本人確認を行い、成功したら [action] を実行する (削除など)。 */
    val verifyThen: (title: String, action: () -> Unit) -> Unit,
    val openNfcSettings: () -> Unit,
    val openSecuritySettings: () -> Unit,
    val requestBluetoothPermission: () -> Unit,
    val makeDiscoverable: () -> Unit,
    val openUrl: (String) -> Unit,
    /** OS のアプリ別言語設定 (Android 13 以降) を開く。 */
    val openAppLanguageSettings: () -> Unit
)

internal enum class NavigationLayout { DRAWER, PERMANENT }

/** 画面幅 840dp 以上で常設サイドバー、それ未満でモーダルドロワー (TCSameuraDamMonitor と同じ基準)。 */
@Composable
internal fun rememberNavigationLayout(): NavigationLayout {
    val windowInfo = LocalWindowInfo.current
    val density = LocalDensity.current
    val widthDp = with(density) { windowInfo.containerSize.width.toDp() }
    return if (widthDp >= 840.dp) NavigationLayout.PERMANENT else NavigationLayout.DRAWER
}

private data class DrawerDestination(val route: String, val labelRes: Int, val icon: ImageVector)

private val destinations = listOf(
    DrawerDestination(Routes.AUTHENTICATOR, R.string.nav_authenticator, Icons.Outlined.Key),
    DrawerDestination(Routes.CREDENTIALS, R.string.nav_credentials, Icons.Outlined.VpnKey),
    DrawerDestination(Routes.LOG, R.string.nav_event_log, Icons.Outlined.History),
    DrawerDestination(Routes.SETTINGS, R.string.nav_settings, Icons.Outlined.Settings),
    DrawerDestination(Routes.ABOUT, R.string.nav_about, Icons.Outlined.Info)
)

private fun titleFor(route: String): Int =
    destinations.firstOrNull { it.route == route }?.labelRes ?: R.string.app_name

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot(viewModel: MainViewModel, actions: UiActions) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route ?: Routes.AUTHENTICATOR
    val currentDocument = if (currentRoute == Routes.DOCUMENT) {
        LegalDocument.fromId(backStackEntry?.arguments?.getString("id"))
    } else {
        null
    }
    val openDocument: (LegalDocument) -> Unit = { doc -> navController.navigate(Routes.document(doc.id)) }
    val layout = rememberNavigationLayout()
    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    var sidebarExpanded by rememberSaveable { mutableStateOf(true) }
    val snackbarHostState = remember { SnackbarHostState() }
    val session by viewModel.session.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.messages.collect { snackbarHostState.showSnackbar(it) }
    }

    val navigate: (String) -> Unit = { route ->
        if (route != currentRoute) {
            navController.navigate(route) {
                popUpTo(Routes.AUTHENTICATOR)
                launchSingleTop = true
            }
        }
    }

    BackHandler(enabled = layout == NavigationLayout.DRAWER && drawerState.isOpen) {
        scope.launch { drawerState.close() }
    }

    val scaffold: @Composable () -> Unit = {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        AutoResizingSingleLineText(
                            text = stringResource(currentDocument?.titleRes ?: titleFor(currentRoute)),
                            style = MaterialTheme.typography.titleLarge
                        )
                    },
                    navigationIcon = {
                        if (currentRoute == Routes.DOCUMENT) {
                            IconButton(onClick = { navController.popBackStack() }) {
                                Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = stringResource(R.string.desc_back))
                            }
                        } else if (layout == NavigationLayout.DRAWER) {
                            IconButton(onClick = { scope.launch { drawerState.open() } }) {
                                Icon(Icons.Outlined.Menu, contentDescription = stringResource(R.string.desc_open_menu))
                            }
                        } else if (!sidebarExpanded) {
                            IconButton(onClick = { sidebarExpanded = true }) {
                                Icon(Icons.Outlined.Menu, contentDescription = stringResource(R.string.desc_expand_sidebar))
                            }
                        }
                    }
                )
            },
            snackbarHost = { SnackbarHost(snackbarHostState) }
        ) { padding ->
            NavHost(
                navController = navController,
                startDestination = Routes.AUTHENTICATOR,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                composable(Routes.AUTHENTICATOR) {
                    AuthenticatorScreen(
                        viewModel = viewModel,
                        actions = actions,
                        onShowCredentials = { navigate(Routes.CREDENTIALS) },
                        onShowLog = { navigate(Routes.LOG) },
                        onShowSettings = { navigate(Routes.SETTINGS) }
                    )
                }
                composable(Routes.CREDENTIALS) { CredentialsScreen(viewModel, actions) }
                composable(Routes.LOG) { EventLogScreen(viewModel) }
                composable(Routes.SETTINGS) { SettingsScreen(viewModel, actions) }
                composable(Routes.ABOUT) { AboutScreen(actions, onOpenDocument = openDocument) }
                composable(
                    Routes.DOCUMENT,
                    arguments = listOf(navArgument("id") { type = NavType.StringType })
                ) { entry ->
                    val document = LegalDocument.fromId(entry.arguments?.getString("id")) ?: LegalDocument.TERMS
                    DocumentScreen(document, actions, onOpenDocument = openDocument)
                }
            }
        }
    }

    when (layout) {
        NavigationLayout.DRAWER -> ModalNavigationDrawer(
            drawerState = drawerState,
            drawerContent = {
                ModalDrawerSheet {
                    DrawerContent(
                        currentRoute = currentRoute,
                        armed = session.armedUntilElapsed != null,
                        onSelect = { route ->
                            scope.launch { drawerState.close() }
                            navigate(route)
                        },
                        onCollapse = null
                    )
                }
            }
        ) { scaffold() }

        NavigationLayout.PERMANENT -> Row(modifier = Modifier.fillMaxSize()) {
            if (sidebarExpanded) {
                PermanentDrawerSheet(modifier = Modifier.width(320.dp).fillMaxHeight()) {
                    DrawerContent(
                        currentRoute = currentRoute,
                        armed = session.armedUntilElapsed != null,
                        onSelect = navigate,
                        onCollapse = { sidebarExpanded = false }
                    )
                }
            }
            Box(modifier = Modifier.weight(1f).fillMaxHeight()) { scaffold() }
        }
    }
}

@Composable
private fun DrawerContent(
    currentRoute: String,
    armed: Boolean,
    onSelect: (String) -> Unit,
    onCollapse: (() -> Unit)?
) {
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .mouseDragScroll(scrollState, Orientation.Vertical)
            .verticalScroll(scrollState)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .semantics { heading() }
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            AutoResizingSingleLineText(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.titleLarge
            )
            if (onCollapse != null) {
                Spacer(modifier = Modifier.weight(1f))
                IconButton(onClick = onCollapse) {
                    Icon(
                        Icons.AutoMirrored.Filled.MenuOpen,
                        contentDescription = stringResource(R.string.desc_collapse_sidebar)
                    )
                }
            }
        }
        Text(
            text = stringResource(if (armed) R.string.drawer_status_armed else R.string.drawer_status_idle),
            style = MaterialTheme.typography.bodySmall,
            color = if (armed) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 8.dp)
        )
        HorizontalDivider()
        Spacer(modifier = Modifier.padding(top = 4.dp))
        destinations.forEachIndexed { index, d ->
            if (index == 3) HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            NavigationDrawerItem(
                icon = { Icon(d.icon, contentDescription = null) },
                label = { Text(stringResource(d.labelRes)) },
                selected = currentRoute == d.route,
                onClick = { onSelect(d.route) },
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
            )
        }
    }
}
