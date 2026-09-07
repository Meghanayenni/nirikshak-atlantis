/**
 * NIRIKSHAK design tokens — light theme.
 *
 * These are the values from `docs/ui_reference.html` §1, which is the visual
 * specification for this interface, and they match DEVELOPER_GUIDE.md §10 exactly. The
 * reference is never read at runtime and never modified; it is translated.
 *
 * The principles these tokens exist to serve, from §10:
 *
 *   - Semantic colour appears ONLY on verdict chips, the inferred marker, the
 *     evidence highlight and focus states. Never on table rows, never as a large
 *     fill. If a screen is more than roughly a tenth colour, something is being
 *     decorated rather than communicated.
 *
 *   - Colour accelerates recognition; it never carries meaning alone. Reports
 *     print in greyscale and a meaningful share of engineers have colour vision
 *     deficiency, so every state pairs its colour with a text label and a
 *     distinct weight or border treatment.
 *
 *   - FAIL is heaviest — solid fill, reversed text — and draws the eye first.
 *     PASS is lightest: a compliant control needs no attention.
 *
 *   - UNKNOWN is dashed and neutral slate, deliberately NOT amber. Abstention
 *     sits off the severity axis, not at the bottom of it. If the interface made
 *     abstention look like a weaker failure, operators would learn to filter it
 *     out and Rule 3 would be defeated at the presentation layer.
 *
 *   - Severity uses ink weight, not colour. Two competing colour scales on one
 *     screen produce a rainbow and destroy the verdict signal.
 */
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: '#17191C', // primary text, solid fills
          2: '#3D444D', // secondary text, severity bars
        },
        muted: '#6B7280', // metadata, column headers
        paper: '#FFFFFF', // cards, tables
        surface: {
          DEFAULT: '#F6F7F9', // page background, hover
          2: '#EDEFF3', // banding, inset panels
        },
        border: {
          DEFAULT: '#E1E5EA', // hairlines
          strong: '#C8CED6',
        },

        // Verdict palette — exactly the reference's values.
        pass: { DEFAULT: '#1E6B4F', bg: '#EDF5F1', br: '#BEDBCC' },
        fail: { DEFAULT: '#9E2B2B', bg: '#FAEDEC', br: '#E6C6C3' },
        unknown: { DEFAULT: '#4A5666', bg: '#EFF2F5', br: '#CFD6DE' },
        inferred: { DEFAULT: '#7A5B12', bg: '#FAF3E3', br: '#E6D6AE' },

        // Links, focus, evidence highlight. The one accent, used sparingly.
        accent: { DEFAULT: '#23527C', bg: '#EEF3F8', br: '#C3D4E5' },
      },
      fontFamily: {
        // The wordmark and the landing headline only. Never on a verdict.
        display: ['Instrument Serif', 'Iowan Old Style', 'Georgia', 'serif'],
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'SF Mono',
          'Menlo',
          'Consolas',
          'Liberation Mono',
          'monospace',
        ],
      },
      /**
       * The type scale.
       *
       * Base is 16px. Everything in the interface is one of these seven steps;
       * no screen invents its own size. §10 permits revising the scale without
       * amending the principles, and this is that revision — the previous 14px
       * base read as a prototype rather than as an operator tool.
       */
      fontSize: {
        micro: ['0.75rem', { lineHeight: '1.1rem' }],   // 12px  column headers, labels
        code: ['0.8125rem', { lineHeight: '1.25rem' }], // 13px  configuration lines
        sm: ['0.875rem', { lineHeight: '1.35rem' }],    // 14px  secondary metadata
        base: ['0.9375rem', { lineHeight: '1.5rem' }],  // 15px  body, tables, controls
        lg: ['1rem', { lineHeight: '1.5rem' }],         // 16px  card titles
        xl: ['1.4375rem', { lineHeight: '1.9rem' }],    // 23px  page titles
        '2xl': ['2rem', { lineHeight: '2.4rem' }],      // 32px  counts
        display: ['clamp(3rem, 9vw, 5.5rem)', { lineHeight: '1.04', letterSpacing: '-0.02em' }],
      },
      borderRadius: {
        DEFAULT: '4px',
        card: '6px',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        // Restrained, per §10. Nothing loops; nothing draws the eye on its own.
        'fade-in': 'fade-in 120ms ease-out',
        'slide-up': 'slide-up 160ms ease-out',
      },
    },
  },
  plugins: [],
};
