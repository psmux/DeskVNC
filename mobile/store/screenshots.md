# Screenshot plan

Screenshots come from the phone UI in mock mode, rendered by
`mobile/scripts/store-screenshots.mjs` in headless, muted Chromium. Nothing is
captured from a real computer, so no real host name, address or desktop can
end up in a store image. Run it again whenever the UI changes:

```sh
cd mobile/scripts
npm install                 # once, Playwright only
node store-screenshots.mjs --serve
```

With `--serve` the script starts the UI's dev server in `mobile/ui` on port
5174 and stops it at the end. Output goes to
`mobile/store/screenshots/out/<device>/`, which git ignores: a framed image
per shot, and the bare screen in `raw/`. Both are at the store's exact size,
so either can be uploaded.

The route names are constants at the top of the script (`ROUTES`). If the UI
moves a screen, change them there.

## Sizes

| Store | Slot | Pixels | Required | Device key |
|---|---|---|---|---|
| App Store | iPhone 6.9 inch | 1320 x 2868 | Yes (1290 x 2796 is also accepted) | `iphone-6.9` |
| App Store | iPad 13 inch | 2064 x 2752 | Yes, because the app runs on iPad | `ipad-13` |
| Google Play | Phone | 1080 x 1920 | 2 to 8 shots | `android-phone` |
| Google Play | 7 inch tablet | 1200 x 1920 | Needed to be listed as tablet ready (check) | `android-tablet-7` |
| Google Play | 10 inch tablet | 1600 x 2560 | Needed to be listed as tablet ready (check) | `android-tablet-10` |
| Google Play | Feature graphic | 1024 x 500 | Yes | `mobile/store/art/feature-graphic.svg` |
| Google Play | App icon | 512 x 512 | Yes | `mobile/icons/out/store/play-icon-512.png` |

Apple scales the 6.9 inch set down for smaller iPhones and the 13 inch set for
smaller iPads, so those two are all that has to be uploaded (check the current
list in App Store Connect, Apple changes it with new devices). Up to 10 per
slot on Apple, 8 on Play.

## The shots, in order

| # | Screen | Caption | What must be on screen |
|---|---|---|---|
| 1 | Demo computer session | Your computer's screen, on your phone | The built in demo desktop, key bar visible |
| 2 | Computers | Every computer you use, at a glance | Four to six mock cards with thumbnails, mixed protocols and OS artwork |
| 3 | Help (Boundary code) | Help someone with a twelve digit code | Number pad with a code half typed |
| 4 | Nearby | Find computers on your network | The radar with a few mock results |
| 5 | Settings | No account, nothing collected | The privacy and about section |

The first shot is the demo session on purpose. It is the one people see in
search results, and it is also exactly what a reviewer can reproduce.

Mock data rules (for the UI agents): names like "Office PC", "Studio Mac",
"Pi in the hall"; addresses only from `192.0.2.x` or `example.com`; no real
person's name anywhere.

Captions are mine to draft and the owner's to reword. They avoid feature
lists and say one thing each.

## Art

`mobile/scripts/export-store-art.sh` turns the SVGs in `mobile/store/art`
into PNGs in `mobile/store/art/out`: the Play feature graphic and a 1200 x 630
promo banner for the site and announcements.
