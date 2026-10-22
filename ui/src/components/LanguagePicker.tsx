/** Language selection, the first thing on the Preferences General tab. */
import type { ReactNode } from "react";
import { useSettings, type LocaleChoice } from "../state/SettingsContext";
import { useT, LOCALES, resolveLocale, type Locale } from "../lib/i18n";
import { classNames } from "../lib/util";

/**
 * The names come from `LOCALES`, which spells each language in itself, so the
 * list is readable whatever the UI is currently showing. The one exception is
 * "Follow System", which is a sentence and does get translated.
 */
export function LanguagePicker(): ReactNode {
  const tr = useT();
  const { settings, update } = useSettings();
  const inUse: Locale = resolveLocale(settings.locale);

  return (
    <div className="border-b border-subtle pb-5">
      <p className="text-sm font-medium text-primary">{tr("Language")}</p>
      <p className="mb-2 text-xs text-tertiary">
        {tr("Follow System uses the language your operating system is set to.")}
      </p>
      <div className="flex flex-wrap gap-2" role="radiogroup" aria-label={tr("Language")}>
        {(["system", ...LOCALES.map((l) => l.id)] as LocaleChoice[]).map((choice) => {
          const label =
            choice === "system"
              ? tr("Follow System")
              : (LOCALES.find((l) => l.id === choice)?.label ?? choice);
          return (
            <button
              key={choice}
              type="button"
              role="radio"
              aria-checked={settings.locale === choice}
              className={classNames(
                "rounded-md border px-3.5 py-1.5 text-sm",
                settings.locale === choice
                  ? "border-accent bg-accent/10 font-medium text-primary"
                  : "border-subtle text-secondary hover:border-strong",
              )}
              onClick={() => update({ locale: choice })}
            >
              {label}
              {choice === "system" ? (
                <span className="ml-1.5 text-xs text-tertiary">
                  {tr("({language})", { language: languageName(inUse) })}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** A language's own name for itself, for the line under "Follow System". */
function languageName(locale: Locale): string {
  return LOCALES.find((l) => l.id === locale)?.label ?? locale;
}
