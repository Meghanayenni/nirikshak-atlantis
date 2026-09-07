import { configure } from '@testing-library/dom';
import '@testing-library/jest-dom/vitest';

/**
 * How long an async query waits before giving up.
 *
 * Testing Library's default is one second, measured against a browser. These
 * tests run the real router, the real providers and the real guards under jsdom,
 * and every screen settles only after four independent stubbed requests have
 * resolved through React's scheduler — so a first paint here regularly lands
 * around 1.5 seconds on an ordinary machine, and further from the default as the
 * application grows a screen.
 *
 * Raising this trades a slower failure for a truthful one. A `findBy` that times
 * out on a page which was about to render correctly reports a bug that does not
 * exist, and teaches whoever sees it to distrust the suite. Nothing here asserts
 * how fast the interface is; every assertion is about what it eventually says.
 */
configure({ asyncUtilTimeout: 5000 });
