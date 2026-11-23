package com.psmux.deskvnc.mobile

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import app.tauri.annotation.Command
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

// Android 17 blocks an app that targets SDK 37 from the local network (every
// computer on the same Wi-Fi, and the Nearby scan) until it holds
// ACCESS_LOCAL_NETWORK, a runtime permission in the Nearby devices group.
// Rust registers this plugin at start (src/localnet.rs) and asks it three
// things: whether the permission is held, to ask for it with the system
// prompt, and to open this app's page in Android settings when the person
// has said no and Android will not ask again.
@TauriPlugin(
  permissions = [
    Permission(strings = [LocalNetworkPlugin.LOCAL_NETWORK], alias = LocalNetworkPlugin.ALIAS)
  ]
)
class LocalNetworkPlugin(private val activity: Activity) : Plugin(activity) {

  // Before Android 17 the permission does not exist and the local network is
  // open to any app with INTERNET, so it counts as held.
  private fun held(): Boolean =
    Build.VERSION.SDK_INT < 37 ||
      activity.checkSelfPermission(LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED

  private fun answer(invoke: Invoke) {
    val out = JSObject()
    out.put("state", if (held()) "granted" else "denied")
    invoke.resolve(out)
  }

  @Command
  fun state(invoke: Invoke) = answer(invoke)

  // Shows the system prompt when Android still allows it. When the person
  // already said no for good, Android answers at once without a prompt, and
  // the state comes back denied either way.
  @Command
  fun ask(invoke: Invoke) {
    if (held()) return answer(invoke)
    requestPermissionForAlias(ALIAS, invoke, "answered")
  }

  @PermissionCallback
  private fun answered(invoke: Invoke) = answer(invoke)

  // This app's page in Android settings, where Permissions, Nearby devices
  // can be switched to Allow. A phone without that page gets the main
  // settings screen instead.
  @Command
  fun openSettings(invoke: Invoke) {
    val appPage = Intent(
      Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
      Uri.fromParts("package", activity.packageName, null)
    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    val anySettings = Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    for (intent in listOf(appPage, anySettings)) {
      try {
        activity.startActivity(intent)
        invoke.resolve()
        return
      } catch (_: ActivityNotFoundException) {
      }
    }
    invoke.reject("This phone has no settings screen to open")
  }

  companion object {
    const val LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
    const val ALIAS = "localNetwork"
  }
}
