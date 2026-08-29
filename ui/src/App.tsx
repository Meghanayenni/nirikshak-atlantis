/**
 * Routing and the route guards.
 *
 * `RequireAuth` and `RequireAdmin` are **UX controls, not security**. They stop a
 * user landing on a page that would 403 and give them a comprehensible message
 * instead of a broken screen. The backend enforces every rule independently:
 * admin endpoints answer 403 to a non-admin, and a resource belonging to another
 * user answers 404 rather than 403 so nothing is learned about which ids exist.
 */
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

import { Card } from '@/components/ui/Primitives';
import { BlockedState } from '@/components/ui/States';
import { useAuth } from '@/hooks/useAuth';
import { AppShell } from '@/layouts/AppShell';
import { ADMIN_ONLY_PATHS } from '@/layouts/navigation';
import { PrioritisationPage } from '@/pages/admin/Prioritisation';
import { SystemHealthPage } from '@/pages/admin/SystemHealth';
import { TrainingPage } from '@/pages/admin/Training';
import { UsersPage } from '@/pages/admin/Users';
import { AuditDetailPage } from '@/pages/shared/AuditDetail';
import { AuditsPage } from '@/pages/shared/Audits';
import { AuditTrailPage } from '@/pages/shared/AuditTrail';
import { DashboardPage } from '@/pages/shared/Dashboard';
import { DeviceDetailPage } from '@/pages/shared/DeviceDetail';
import { DevicesPage } from '@/pages/shared/Devices';
import { FindingDetailPage } from '@/pages/shared/FindingDetail';
import { LoginPage } from '@/pages/shared/Login';
import {
  CompliancePage,
  DriftPage,
  FindingsPage,
  NotFoundPage,
  ProfilePage,
  RemediationPage,
  ReportsPage,
  VendorPacksPage,
} from '@/pages/shared/Misc';

function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

function RequireAdmin({ children }: { children: ReactNode }) {
  const { isAdmin } = useAuth();
  const location = useLocation();
  if (!isAdmin) {
    return (
      <Card>
        <BlockedState
          title="Administrator access required"
          reason={
            `${location.pathname} is restricted to administrators. This is enforced by the ` +
            'server, which refuses the underlying request regardless of what this interface ' +
            'shows.'
          }
        />
      </Card>
    );
  }
  return <>{children}</>;
}

/** Kept beside the nav list so the two cannot drift apart. */
export function isAdminPath(path: string): boolean {
  return ADMIN_ONLY_PATHS.includes(path);
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
        <Route path="/audits" element={<AuditsPage />} />
        <Route path="/audits/:auditId" element={<AuditDetailPage />} />
        <Route path="/audits/:auditId/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/remediation" element={<RemediationPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/trail" element={<AuditTrailPage />} />
        <Route path="/profile" element={<ProfilePage />} />

        {/* Admin-only. The backend refuses these independently. */}
        <Route
          path="/prioritisation"
          element={
            <RequireAdmin>
              <PrioritisationPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/training"
          element={
            <RequireAdmin>
              <TrainingPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/packs"
          element={
            <RequireAdmin>
              <VendorPacksPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/users"
          element={
            <RequireAdmin>
              <UsersPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/drift"
          element={
            <RequireAdmin>
              <DriftPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/health"
          element={
            <RequireAdmin>
              <SystemHealthPage />
            </RequireAdmin>
          }
        />

        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
