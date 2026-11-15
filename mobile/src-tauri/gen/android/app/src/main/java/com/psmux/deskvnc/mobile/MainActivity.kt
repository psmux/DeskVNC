package com.psmux.deskvnc.mobile

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    keepAboveKeyboard()
    askForLocalNetwork()
  }

  // Almost every computer this app reaches is on the local network, so ask
  // for it at the first launch rather than letting the first Connect hang.
  private fun askForLocalNetwork() {
    if (Build.VERSION.SDK_INT < 37) return
    if (checkSelfPermission(LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) return
    requestPermissions(arrayOf(LOCAL_NETWORK), 7301)
  }

  private companion object {
    const val LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
  }

  // Edge to edge, Android no longer shrinks the window for the soft
  // keyboard (adjustResize only hands the app the keyboard's inset), and the
  // WebView does not shrink on its own, so the keyboard covered the sign in
  // fields and their buttons. Pad the content by the keyboard's height: the
  // WebView gets shorter, the page's viewport with it, and the focused field
  // scrolls into the space that is left. The system bars stay under the
  // page, which keeps its own safe area padding for them.
  private fun keepAboveKeyboard() {
    val content = findViewById<View>(android.R.id.content) ?: return
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
      if (view.paddingBottom != keyboard) view.setPadding(0, 0, 0, keyboard)
      insets
    }
  }
}
