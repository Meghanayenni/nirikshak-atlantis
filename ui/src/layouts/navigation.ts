/**
 * The navigation, in two groups.
 *
 * **Pipeline** is the product as the problem statement states it:
 * `Ingest → Parse → Comply → Remediate → Report`. Nothing is added to that list
 * — a screen that is not one of those five stages does not belong in it, however
 * useful it is.
 *
 * **Beyond the pipeline** is everything built on top of that base: how the
 * platform descriptions are maintained, what has been recorded, and which
 * optional capabilities this deployment actually has. They are capabilities in
 * their own right rather than steps in a run, which is why they are named as a
 * separate group instead of appended to the first.
 *
 * This list is not a security boundary. The backend enforces every rule
 * independently: admin endpoints answer 403 to a non-admin, and a resource
 * belonging to another user answers 404 rather than 403 so nothing is learned
 * about which ids exist.
 */
import {
  Activity,
  Boxes,
  FileText,
  HardDrive,
  ScrollText,
  ShieldCheck,
  Wrench,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  to: string;
  label: string;
  /** The pipeline stage this screen belongs to. Shown beside the label. */
  stage: string;
  icon: LucideIcon;
}

/** The pipeline, in execution order. */
export const PIPELINE_NAV: NavItem[] = [
  { to: '/devices', label: 'Devices', stage: 'Ingest · Parse', icon: HardDrive },
  { to: '/compliance', label: 'Compliance', stage: 'Evaluate', icon: ShieldCheck },
  { to: '/remediation', label: 'Remediation', stage: 'Resolve', icon: Wrench },
  { to: '/reports', label: 'Reports', stage: 'Report', icon: FileText },
];

/**
 * Built on top of the pipeline, not part of it.
 *
 * `stage` here names what the screen is for rather than a pipeline step, because
 * none of these is one.
 */
export const SUPPORT_NAV: NavItem[] = [
  { to: '/packs', label: 'Vendor packs', stage: 'How each platform is read', icon: Boxes },
  { to: '/activity', label: 'Activity log', stage: 'Every recorded action', icon: Activity },
  { to: '/status', label: 'Status', stage: 'Installed capabilities', icon: ScrollText },
];

export const ALL_NAV: NavItem[] = [...PIPELINE_NAV, ...SUPPORT_NAV];

export function titleFor(pathname: string): string {
  const match = ALL_NAV.filter((item) => pathname.startsWith(item.to)).sort(
    (a, b) => b.to.length - a.to.length,
  )[0];
  return match?.label ?? 'Nirikshak';
}
