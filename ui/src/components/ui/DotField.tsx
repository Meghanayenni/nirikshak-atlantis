/**
 * The dot field behind the landing page.
 *
 * A grid of faint dots on paper, drawn once to a canvas, with the dots near the
 * pointer lifting slightly in weight and size. It is the one decorative surface
 * in this product, and it is deliberately monochrome: inside the application the
 * accent means "link, focus, cited evidence" and the verdict palette means PASS,
 * FAIL and UNKNOWN, so a coloured field here would teach the eye a colour that
 * means something specific two screens later.
 *
 * Why canvas rather than a CSS `radial-gradient` tile: the response to the
 * pointer is per-dot, and doing that with elements would mean a few thousand
 * nodes and a layout pass per frame.
 *
 * **It never runs when nobody is looking.** The animation loop starts on pointer
 * movement and stops itself once the field has settled back, so an idle tab
 * costs nothing. `prefers-reduced-motion` skips the interaction entirely and
 * paints the static grid, which is the whole design minus the flourish.
 */
import { useEffect, useRef } from 'react';

const SPACING = 26;
/** Pointer influence radius, in pixels. */
const REACH = 150;
const BASE_RADIUS = 1;
const LIFT_RADIUS = 2.4;
const BASE_ALPHA = 0.14;
const LIFT_ALPHA = 0.55;
/** How fast a dot returns to rest. Lower is slower. */
const EASE = 0.12;

export function DotField({ className = '' }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

    let width = 0;
    let height = 0;
    let frame = 0;
    /** Per-dot eased intensity, 0 at rest. Indexed row-major. */
    let energy = new Float32Array(0);
    let cols = 0;
    let rows = 0;

    // Off-screen until the pointer arrives, so nothing lifts on first paint.
    const pointer = { x: -9999, y: -9999 };

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const rect = canvas!.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas!.width = Math.floor(width * dpr);
      canvas!.height = Math.floor(height * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);

      cols = Math.ceil(width / SPACING) + 1;
      rows = Math.ceil(height / SPACING) + 1;
      energy = new Float32Array(cols * rows);
      draw();
    }

    function draw() {
      ctx!.clearRect(0, 0, width, height);
      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const e = energy[row * cols + col];
          const x = col * SPACING;
          const y = row * SPACING;
          const radius = BASE_RADIUS + (LIFT_RADIUS - BASE_RADIUS) * e;
          const alpha = BASE_ALPHA + (LIFT_ALPHA - BASE_ALPHA) * e;

          ctx!.beginPath();
          ctx!.arc(x, y, radius, 0, Math.PI * 2);
          // ink (#17191C) at a very low alpha — a grey that belongs to the
          // palette rather than an arbitrary one.
          ctx!.fillStyle = `rgba(23, 25, 28, ${alpha})`;
          ctx!.fill();
        }
      }
    }

    /** One eased step. Returns true while anything is still moving. */
    function step(): boolean {
      let moving = false;
      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const i = row * cols + col;
          const dx = col * SPACING - pointer.x;
          const dy = row * SPACING - pointer.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          // Smoothstep falloff: no hard edge where the influence ends.
          let target = 0;
          if (distance < REACH) {
            const t = 1 - distance / REACH;
            target = t * t * (3 - 2 * t);
          }

          const next = energy[i] + (target - energy[i]) * EASE;
          if (Math.abs(next - energy[i]) > 0.001) moving = true;
          energy[i] = next;
        }
      }
      return moving;
    }

    function loop() {
      const moving = step();
      draw();
      // Stop once the field has settled. An idle tab should not hold a rAF.
      frame = moving ? requestAnimationFrame(loop) : 0;
    }

    function onPointerMove(event: PointerEvent) {
      const rect = canvas!.getBoundingClientRect();
      pointer.x = event.clientX - rect.left;
      pointer.y = event.clientY - rect.top;
      if (!frame) frame = requestAnimationFrame(loop);
    }

    function onPointerLeave() {
      pointer.x = -9999;
      pointer.y = -9999;
      if (!frame) frame = requestAnimationFrame(loop);
    }

    resize();
    window.addEventListener('resize', resize);

    if (!reduced) {
      window.addEventListener('pointermove', onPointerMove, { passive: true });
      document.addEventListener('pointerleave', onPointerLeave);
    }

    return () => {
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onPointerMove);
      document.removeEventListener('pointerleave', onPointerLeave);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
    />
  );
}
