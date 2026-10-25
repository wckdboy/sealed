/**
 * Runtime branding.
 *
 * The bake-time `brand/brand.json` is the *default*; `/v1/brand` is the truth. An
 * operator renames the instance from the admin panel (saved in the database), and
 * every client picks it up on next load without a rebuild and without a fork —
 * which is the whole point of keeping brand out of the wire formats.
 *
 * Baked values are applied synchronously so the first paint is never blank; fetched
 * values then replace them.
 */

import raw from '../../brand/brand.json';

export interface Brand {
  name: string;
  app: string;
  tagline: string;
  accent: string;
  homepage: string;
  dmca_default: string;
  account_label: string;
  /** Optional short mark shown before the name (e.g. "◈"). */
  logo?: string;
}

/** Mutable: `loadBrand()` refines it from the API. */
export const brand: Brand = {
  ...raw,
  name: (import.meta.env.VITE_BRAND_NAME as string | undefined) ?? raw.name,
  accent: (import.meta.env.VITE_BRAND_ACCENT as string | undefined) ?? raw.accent,
};

/** Turn an accent into a translucent colour for soft fills (no colour library). */
function soft(accent: string, alpha: number): string {
  const hex = accent.replace('#', '');
  if (hex.length !== 6) return `rgba(255, 61, 110, ${alpha})`;
  const r = parseInt(hex.slice(0, 2), 16);
  const g = parseInt(hex.slice(2, 4), 16);
  const b = parseInt(hex.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

/** Paint brand values onto the document shell. Safe to call more than once. */
export function applyBrand(): void {
  document.title = `${brand.name} — ${brand.tagline}`;
  const root = document.documentElement;
  root.style.setProperty('--accent', brand.accent);
  root.style.setProperty('--accent-soft', soft(brand.accent, 0.16));
  root.style.setProperty('--accent-line', soft(brand.accent, 0.45));
  const name = document.getElementById('brand-name');
  if (name) name.textContent = brand.name;
  const tagline = document.getElementById('brand-tagline');
  if (tagline) tagline.textContent = brand.tagline;
  const logo = document.getElementById('brand-logo');
  if (logo) logo.textContent = brand.logo ?? '';
}

/**
 * Fetch the instance's current brand. A failure is not fatal: baked defaults are
 * already applied and a rename is cosmetic, so this never blocks the app.
 */
export async function loadBrand(apiBase = ''): Promise<void> {
  try {
    const res = await fetch(`${apiBase}/v1/brand`, { headers: { accept: 'application/json' } });
    if (!res.ok) return;
    const doc = (await res.json()) as Partial<Brand>;
    for (const key of ['name', 'tagline', 'accent', 'logo'] as const) {
      const value = doc[key];
      if (typeof value === 'string' && value.trim()) {
        (brand as unknown as Record<string, string>)[key] = value;
      }
    }
    applyBrand();
  } catch {
    // Offline or blocked: keep the baked brand.
  }
}
