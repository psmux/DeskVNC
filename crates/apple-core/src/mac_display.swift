// Executed over the already authenticated SSH channel; not installed on disk.
import Foundation
import CoreGraphics

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let display = CGMainDisplayID()
guard CGDisplayIsBuiltin(display) != 0 else {
    fail("The main display is not the physical built-in panel; refusing to modify a virtual or unselected display.")
}
guard let current = CGDisplayCopyDisplayMode(display),
      let modes = CGDisplayCopyAllDisplayModes(display, [kCGDisplayShowDuplicateLowResolutionModes: true] as CFDictionary) as? [CGDisplayMode] else {
    fail("Cannot enumerate physical display modes.")
}
let arguments = Array(CommandLine.arguments.dropFirst())
let action = arguments.first ?? "list"

if action == "set" {
    guard arguments.count == 3,
          let width = Int(arguments[1]), let height = Int(arguments[2]),
          width >= 640, width <= 8192, height >= 480, height <= 8192 else {
        fail("Invalid requested physical display dimensions.")
    }
    let candidates = modes.filter { $0.width == width && $0.height == height && $0.pixelWidth <= 4096 && $0.pixelHeight <= 4096 }
    // Prefer the same HiDPI ratio as the current mode.
    let ratio = Double(current.pixelWidth) / Double(current.width)
    guard let chosen = candidates.min(by: {
        abs(Double($0.pixelWidth) / Double($0.width) - ratio) < abs(Double($1.pixelWidth) / Double($1.width) - ratio)
    }) else { fail("Requested resolution is not an available physical display mode.") }
    let status = CGDisplaySetDisplayMode(display, chosen, nil)
    guard status == .success, CGDisplayCopyDisplayMode(display)?.ioDisplayModeID == chosen.ioDisplayModeID else {
        _ = CGDisplaySetDisplayMode(display, current, nil)
        fail("macOS rejected the display mode; original mode restored where possible.")
    }
} else if action == "restore" {
    guard arguments.count == 3,
          let original = Int32(arguments[1]), let lastApplied = Int32(arguments[2]),
          let chosen = modes.first(where: { $0.ioDisplayModeID == original }) else {
        fail("Original physical display mode is no longer available.")
    }
    guard current.ioDisplayModeID == lastApplied else {
        fail("The display was changed outside DeskVNC; leaving it unchanged.")
    }
    guard CGDisplaySetDisplayMode(display, chosen, nil) == .success else {
        fail("macOS rejected restoration of the original physical display mode.")
    }
} else if action != "list" {
    fail("Unknown display action.")
}

guard let effective = CGDisplayCopyDisplayMode(display) else { fail("Cannot read effective display mode.") }
let point = CGEvent(source: nil)?.location ?? .zero
let result: [String: Any] = [
    "displayId": display,
    "originalModeId": current.ioDisplayModeID,
    "currentModeId": effective.ioDisplayModeID,
    "width": effective.width,
    "height": effective.height,
    "pixelWidth": effective.pixelWidth,
    "pixelHeight": effective.pixelHeight,
    "pointerX": point.x,
    "pointerY": point.y,
    "modes": modes.map { mode -> [String: Any] in
        ["id": mode.ioDisplayModeID, "width": mode.width, "height": mode.height,
         "pixelWidth": mode.pixelWidth, "pixelHeight": mode.pixelHeight]
    }
]
let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
print(String(decoding: data, as: UTF8.self))
