/**
 * Role-aware navigation.
 *
 * Two things this list is NOT:
 *
 *   It is **not a security boundary.** Hiding an admin entry stops a user
 *   stumbling into a page that would 403; the backend enforces the rule. Every
 *   admin route also guards itself, and every admin endpoint refuses a non-admin
 *   caller regardless of what this file says.
 *
 *   It is **not a promise that a page works.** `availability` records whether the
 *   backend can actually serve the screen. Entries marked `unavailable` render a
 *   page that says which capability is missing, rather than an empty table that
 *   would read as "nothing to report".
 */
import {
  Activity,
  Boxes,
  ClipboardList,
  FileText,
  GitCompare,
  GraduationCap,
  HeartPulse,
  LayoutDashboard,
  ListOrdered,
  Network,
  ScrollText,
  ShieldCheck,
  Users,
  Wrench,
  type LucideIcon,
} from 'lucide-react';

export type Availability = 'available' | 'partial' | 'unavailable';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  availability: Availability;
  /** Shown on the page when availability is not `available`. */
  note?: string;
}

export const ADMIN_NAV: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, availability: 'available' },
  { to: '/devices', label: 'Devices', icon: Network, availability: 'available' },
  { to: '/audits', label: 'Audits', icon: ClipboardList, availability: 'available' },
  { to: '/findings', label: 'Findings', icon: ShieldCheck, availability: 'available' },
  { to: '/prioritisation', label: 'Prioritisation', icon: ListOrdered, availability: 'available' },
  {
    to: '/compliance',
    label: 'Compliance',
    icon: FileText,
    availability: 'partial',
    note:
      'Framework mappings are not available. Every rule ships with an empty framework list, ' +
      'because writing a CIS, NIST, STIG or ISO identifier without having read the benchmark ' +
      'would be inventing it. The checks below are NIRIKSHAK’s own.',
  },
  {
    to: '/remediation',
    label: 'Remediation',
    icon: Wrench,
    availability: 'partial',
    note:
      'The vetted snippet library is empty, so no command is offered for any rule. A snippet ' +
      'cannot exist without a person who read a vendor document and checked the commands ' +
      'against it.',
  },
  {
    to: '/drift',
    label: 'Drift Detection',
    icon: GitCompare,
    availability: 'unavailable',
    note:
      'The backend exposes no drift capability: there is no snapshot store and no comparison ' +
      'endpoint. Computing drift in the browser would make this interface a second analysis ' +
      'engine disagreeing with the first.',
  },
  { to: '/training', label: 'Training Center', icon: GraduationCap, availability: 'available' },
  {
    to: '/packs',
    label: 'Vendor Packs',
    icon: Boxes,
    availability: 'partial',
    note:
      'There is no vendor-pack listing endpoint. The versions shown are the ones recorded on ' +
      'audit runs, which is what the backend actually reports.',
  },
  { to: '/users', label: 'Users', icon: Users, availability: 'available' },
  { to: '/reports', label: 'Reports', icon: ScrollText, availability: 'available' },
  { to: '/trail', label: 'Audit Trail', icon: Activity, availability: 'available' },
  { to: '/health', label: 'System Health', icon: HeartPulse, availability: 'available' },
];

export const USER_NAV: NavItem[] = [
  { to: '/dashboard', label: 'My Dashboard', icon: LayoutDashboard, availability: 'available' },
  { to: '/devices', label: 'My Devices', icon: Network, availability: 'available' },
  { to: '/audits', label: 'My Audits', icon: ClipboardList, availability: 'available' },
  { to: '/findings', label: 'My Findings', icon: ShieldCheck, availability: 'available' },
  {
    to: '/compliance',
    label: 'My Compliance',
    icon: FileText,
    availability: 'partial',
    note: 'Framework mappings are not available; the checks shown are NIRIKSHAK’s own.',
  },
  {
    to: '/remediation',
    label: 'My Remediation',
    icon: Wrench,
    availability: 'partial',
    note: 'The vetted snippet library is empty, so no command is offered for any rule.',
  },
  { to: '/reports', label: 'My Reports', icon: ScrollText, availability: 'available' },
  { to: '/trail', label: 'Audit Trail', icon: Activity, availability: 'available' },
  { to: '/profile', label: 'My Profile', icon: Users, availability: 'available' },
];

/** Routes only an administrator may open. Mirrors the backend's own 403 set. */
export const ADMIN_ONLY_PATHS = [
  '/prioritisation',
  '/training',
  '/packs',
  '/users',
  '/drift',
  '/health',
];

export function navFor(isAdmin: boolean): NavItem[] {
  return isAdmin ? ADMIN_NAV : USER_NAV;
}
