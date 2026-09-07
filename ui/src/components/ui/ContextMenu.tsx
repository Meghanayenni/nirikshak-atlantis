/**
 * A right-click menu for a table row.
 *
 * Right-click is a shortcut, never the only way to reach an action. Every item
 * this menu offers is also reachable from a visible control in the row, because
 * a destructive action that exists only behind a gesture is one a keyboard user
 * cannot perform and a new operator cannot find.
 *
 * The menu closes on Escape, on scroll, and on any click outside it. It is
 * positioned in viewport coordinates and clamped to the window so an item near
 * the right or bottom edge does not open off-screen.
 */
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';

export interface MenuItem {
  id: string;
  label: string;
  icon?: LucideIcon;
  /** Destructive items carry the FAIL colour and sit below a separator. */
  destructive?: boolean;
  disabled?: boolean;
  /** Shown under the label when the item is disabled, so the reason is legible. */
  hint?: string;
  onSelect: () => void;
}

export interface MenuAnchor {
  x: number;
  y: number;
  items: MenuItem[];
}

export function ContextMenu({ anchor, onClose }: { anchor: MenuAnchor | null; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });

  useLayoutEffect(() => {
    if (!anchor || !ref.current) return;
    const { offsetWidth: w, offsetHeight: h } = ref.current;
    setPos({
      x: Math.min(anchor.x, window.innerWidth - w - 8),
      y: Math.min(anchor.y, window.innerHeight - h - 8),
    });
  }, [anchor]);

  useEffect(() => {
    if (!anchor) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    const onAway = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node)) onClose();
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('mousedown', onAway);
    window.addEventListener('scroll', onClose, true);
    window.addEventListener('resize', onClose);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('mousedown', onAway);
      window.removeEventListener('scroll', onClose, true);
      window.removeEventListener('resize', onClose);
    };
  }, [anchor, onClose]);

  if (!anchor) return null;

  return (
    <div
      ref={ref}
      role="menu"
      className="fixed z-50 min-w-[15rem] rounded-card border border-border bg-paper py-1 shadow-lg
                 animate-fade-in"
      style={{ left: pos.x, top: pos.y }}
    >
      {anchor.items.map((item, index) => {
        const separated = item.destructive && !anchor.items[index - 1]?.destructive && index > 0;
        return (
          <div key={item.id}>
            {separated && <div className="my-1 border-t border-border" aria-hidden="true" />}
            <button
              type="button"
              role="menuitem"
              disabled={item.disabled}
              onClick={() => {
                onClose();
                item.onSelect();
              }}
              className={`flex w-full items-start gap-2 px-3 py-1.5 text-left text-base
                disabled:cursor-not-allowed disabled:opacity-60
                ${
                  item.destructive
                    ? 'text-fail enabled:hover:bg-fail-bg'
                    : 'text-ink enabled:hover:bg-surface'
                }`}
            >
              {item.icon && <item.icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />}
              <span className="min-w-0">
                <span className="block">{item.label}</span>
                {item.disabled && item.hint && (
                  <span className="block text-micro text-muted">{item.hint}</span>
                )}
              </span>
            </button>
          </div>
        );
      })}
    </div>
  );
}
