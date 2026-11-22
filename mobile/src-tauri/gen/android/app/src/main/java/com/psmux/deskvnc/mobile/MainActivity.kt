package com.psmux.deskvnc.mobile

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
  }

  // Android 17's local network permission is asked for where it is needed,
  // by LocalNetworkPlugin: when Nearby looks around and when a connect goes
  // to a computer on this network.

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
