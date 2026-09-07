/**
 * The landing page.
 *
 * No navigation bar: one claim, one sentence, one way in. An operator who
 * arrives here either signs in or has no business further along.
 *
 * The field behind the title is the one decorative surface in this product, and
 * it is monochrome on purpose. Inside the application the accent means "link,
 * focus, cited evidence" and the verdict palette means PASS, FAIL and UNKNOWN;
 * a saturated field here would teach the eye a colour that means something
 * specific two screens later. The dots respond to the pointer because a page
 * that answers the cursor reads as a working instrument rather than a poster —
 * which is the impression this product wants before anyone has seen a verdict.
 *
 * The tagline reveals rather than appearing, and reveals without a caret. See
 * `Typewriter` for why.
 */
import { Link } from 'react-router-dom';

import { DotField } from '@/components/ui/DotField';
import { Typewriter } from '@/components/ui/Typewriter';
import { useAuth } from '@/hooks/useAuth';

const TAGLINE = 'Vendor-agnostic compliance auditing for network configurations.';

export function LandingPage() {
  const { isAuthenticated } = useAuth();

  return (
    <div className="relative min-h-screen overflow-hidden bg-paper">
      <DotField />

      {/*
        A single very faint wash, sitting over the dots and under the text. It
        pulls the eye to the centre of the page without competing with the grid;
        nothing here exceeds 8% alpha.
      */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(58rem 34rem at 50% 32%, rgba(255,255,255,0.86), transparent 72%),' +
            'radial-gradient(70rem 40rem at 50% -12%, rgba(35,82,124,0.07), transparent 70%)',
        }}
      />

      <main className="relative flex min-h-screen flex-col items-center justify-center px-6 py-16">
        <div className="w-full max-w-3xl text-center">
          <div className="mx-auto mb-8 flex items-center justify-center gap-3" aria-hidden="true">
            <span className="h-px w-16 bg-border-strong" />
            <span className="h-1.5 w-1.5 rotate-45 bg-accent/50" />
            <span className="h-px w-16 bg-border-strong" />
          </div>

          <p className="text-micro uppercase tracking-[0.2em] text-accent">
            AI suggests. Rules decide.
          </p>

          <h1 className="mt-6 font-display text-display text-ink">Nirikshak</h1>

          <p className="mx-auto mt-7 max-w-xl text-lg leading-relaxed text-ink-2">
            <Typewriter text={TAGLINE} speed={24} delay={420} />
            <br className="hidden sm:block" />
            <span className="mt-1 inline-block">Every verdict cites the line it rests on.</span>
          </p>

          <div className="mt-10 flex items-center justify-center">
            <Link
              to={isAuthenticated ? '/devices' : '/login'}
              className="inline-flex h-12 items-center justify-center rounded-full bg-ink px-9
                         text-lg font-medium text-white transition-colors hover:bg-ink-2"
            >
              {isAuthenticated ? 'Open workspace' : 'Sign in'}
            </Link>
          </div>
        </div>

        <p className="absolute bottom-10 text-micro uppercase tracking-[0.24em] text-muted">
          Offline · Evidence-linked · Deterministic
        </p>
      </main>
    </div>
  );
}
