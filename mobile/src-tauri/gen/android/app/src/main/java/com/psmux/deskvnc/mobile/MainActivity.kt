package com.psmux.deskvnc.mobile

import android.os.Bundle
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import java.util.Locale

class MainActivity : TauriActivity() {
  private var webView: WebView? = null

  // The system bars and cutout as "top,right,bottom,left" in CSS pixels.
  @Volatile private var safeArea = "0,0,0,0"

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    watchInsets()
  }

  // Android 17's local network permission is asked for where it is needed,
  // by LocalNetworkPlugin: when Nearby looks around and when a connect goes
  // to a computer on this network.

  // Wry calls this before it loads the page, so the bridge is there from the
  // first script on.
  override fun onWebViewCreate(webView: WebView) {
    this.webView = webView
    webView.addJavascriptInterface(SafeAreaBridge(), "DeskVNCSafeArea")
    webView.addJavascriptInterface(SystemBarsBridge(), "DeskVNCSystemBars")
    sendSafeArea()
  }

  inner class SafeAreaBridge {
    @JavascriptInterface fun read(): String = safeArea
  }

  // The colour of the status bar and navigation bar icons. enableEdgeToEdge
  // picks it from the phone's dark mode, once, at start: dark icons on a
  // phone in light mode, which left the clock and battery dark on the
  // session's black stage, and on the dark theme's home screen when that
  // theme was picked in Settings. The page knows what it draws under the
  // bars, so it says (src/lib/systemBars.ts) and this applies it.
  inner class SystemBarsBridge {
    @JavascriptInterface fun set(icons: String) {
      if (icons != "light" && icons != "dark") return
      runOnUiThread {
        // A "light" bar in Android's terms has a light backdrop, so dark icons.
        val lightBackdrop = icons == "dark"
        val controller = WindowCompat.getInsetsController(window, window.decorView)
        controller.isAppearanceLightStatusBars = lightBackdrop
        controller.isAppearanceLightNavigationBars = lightBackdrop
      }
    }
  }

  // Edge to edge, Android no longer shrinks the window for the soft
  // keyboard (adjustResize only hands the app the keyboard's inset), and the
  // WebView does not shrink on its own, so the keyboard covered the sign in
  // fields and their buttons. Pad the content by the keyboard's height: the
  // WebView gets shorter, the page's viewport with it, and the focused field
  // scrolls into the space that is left.
  //
  // The system bars stay under the page. The WebView reports only the
  // display cutout as env(safe-area-inset-*), not the status bar or the
  // gesture bar, so a phone held sideways had the status bar over the
  // session's connection chip and toolbar pill. Measure the bars and the
  // cutout here and hand them to the page (src/lib/safeArea.ts).
  private fun watchInsets() {
    val content = findViewById<View>(android.R.id.content) ?: return
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
      if (view.paddingBottom != keyboard) view.setPadding(0, 0, 0, keyboard)
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
      )
      // With the keyboard up the WebView already ends above it, and so above
      // the gesture bar.
      val bottom = maxOf(0, bars.bottom - keyboard)
      val density = resources.displayMetrics.density
      val next = intArrayOf(bars.top, bars.right, bottom, bars.left)
        .joinToString(",") { String.format(Locale.ROOT, "%.2f", it / density) }
      if (next != safeArea) {
        safeArea = next
        sendSafeArea()
      }
      insets
    }
  }

  private fun sendSafeArea() {
    val view = webView ?: return
    val script = "window.__deskvncSafeArea&&window.__deskvncSafeArea('$safeArea')"
    view.post { view.evaluateJavascript(script, null) }
  }
}
