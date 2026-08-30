/**
 * useTheme — light/dark with three states, not two.
 *
 *   "auto"  (default) follow the operating system via
 *           `prefers-color-scheme`; no attribute is set and the CSS media
 *           query decides.
 *   "light" / "dark"  an explicit choice, written to
 *           `document.documentElement[data-theme]`, which the stylesheet
 *           gives higher precedence than the media query.
 *
 * The choice persists in localStorage under a key scoped to this app's
 * backend canister id — every app on the gateway shares one origin, so an
 * unscoped key would let one project silently set another's theme.
 *
 * The stored value is applied in `useLayoutEffect`, i.e. before paint, so
 * a reload does not flash the wrong theme.
 */
import { useCallback, useLayoutEffect, useState } from "react";
import { BACKEND_CANISTER_ID } from "./thebes";

export type Theme = "auto" | "light" | "dark";

const KEY = `thebes-theme:${BACKEND_CANISTER_ID}`;

function stored(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "auto";
  } catch {
    return "auto"; // storage blocked — follow the OS
  }
}

function apply(theme: Theme) {
  const root = document.documentElement;
  if (theme === "auto") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

/** True when the OS currently prefers dark. */
function osPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(stored);

  useLayoutEffect(() => {
    apply(theme);
  }, [theme]);

  const set = useCallback((next: Theme) => {
    setTheme(next);
    try {
      if (next === "auto") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, next);
    } catch {
      /* storage blocked — the in-memory choice still applies */
    }
  }, []);

  /** What the user actually sees right now. */
  const effective: "light" | "dark" =
    theme === "auto" ? (osPrefersDark() ? "dark" : "light") : theme;

  /** Flip to the opposite of what is on screen. */
  const toggle = useCallback(() => {
    set(effective === "dark" ? "light" : "dark");
  }, [effective, set]);

  return { theme, effective, set, toggle };
}
