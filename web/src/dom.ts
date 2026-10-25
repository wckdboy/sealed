/**
 * Tiny DOM helpers shared by the shell and the admin panel.
 *
 * Deliberately framework-free: the whole point of this client is that its first
 * paint is a few KB, and a virtual-DOM library would be a larger download than the
 * application code.
 */

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | number> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'boolean') {
      if (v) node.setAttribute(k, '');
    } else node.setAttribute(k, String(v));
  }
  for (const child of children) node.append(child as Node | string);
  return node;
}

export function panel(...children: (Node | string)[]): HTMLElement {
  return el('section', { class: 'panel' }, ...children);
}

export function bytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let u = 0;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u++;
  }
  return `${v.toFixed(v < 10 && u > 0 ? 1 : 0)} ${units[u]}`;
}

export function when(unix: number | null | undefined): string {
  if (!unix) return 'never';
  const d = new Date(unix * 1000);
  const mins = Math.round((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return d.toISOString().slice(0, 10);
}

export function showError(err: unknown): string {
  const anyErr = err as { code?: string; message?: string };
  if (anyErr?.code && anyErr?.message) return `${anyErr.code}: ${anyErr.message}`;
  return err instanceof Error ? err.message : String(err);
}

/** A labelled input row. */
export function field(label: string, input: HTMLElement): HTMLElement {
  return el('label', {}, label, input);
}
