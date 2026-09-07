/**
 * A line that appears a character at a time.
 *
 * Two decisions make this read as "settling into place" rather than as someone
 * typing:
 *
 *   - **No caret.** A blinking block is the visual cliché of a terminal, and
 *     this is a headline, not a shell. Without it the eye reads the sentence
 *     arriving rather than being keyed in.
 *
 *   - **Each character fades in over its own short window** instead of snapping
 *     from absent to present. The reveal advances on a timer; the softness comes
 *     from CSS transitions on characters that have already been committed, so
 *     the two run independently and the text never stutters when a frame is
 *     dropped.
 *
 * The full sentence is always in the DOM. Characters not yet reached are
 * transparent, not missing, so the paragraph reserves its final height on first
 * paint — no reflow as it fills — and a screen reader gets the whole line at
 * once from the `aria-label`, never a partial one being mutated underneath it.
 *
 * `prefers-reduced-motion` renders the finished sentence immediately.
 */
import { useEffect, useRef, useState } from 'react';

export interface TypewriterProps {
  text: string;
  /** Milliseconds between characters. */
  speed?: number;
  /** Milliseconds to wait before the first character. */
  delay?: number;
  className?: string;
}

export function Typewriter({ text, speed = 26, delay = 300, className = '' }: TypewriterProps) {
  const [revealed, setRevealed] = useState(0);
  const reducedRef = useRef(false);

  useEffect(() => {
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    reducedRef.current = reduced;

    if (reduced) {
      setRevealed(text.length);
      return;
    }

    setRevealed(0);
    let index = 0;
    let timer = 0;

    const start = window.setTimeout(function tick() {
      index += 1;
      setRevealed(index);
      if (index < text.length) {
        // Whitespace advances immediately: pausing on a space is what makes a
        // reveal feel mechanical, because a real sentence has no gap there.
        const wait = text[index] === ' ' ? 0 : speed;
        timer = window.setTimeout(tick, wait);
      }
    }, delay);

    return () => {
      window.clearTimeout(start);
      window.clearTimeout(timer);
    };
  }, [text, speed, delay]);

  return (
    <span className={className} aria-label={text}>
      {Array.from(text).map((character, index) => (
        <span
          // The text is fixed for the life of the component, so the index is a
          // stable identity here.
          key={index}
          aria-hidden="true"
          style={{
            opacity: index < revealed ? 1 : 0,
            transition: reducedRef.current ? 'none' : 'opacity 420ms ease-out',
          }}
        >
          {character}
        </span>
      ))}
    </span>
  );
}
