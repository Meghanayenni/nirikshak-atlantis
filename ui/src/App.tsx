/**
 * Routing.
 *
 * Seven destinations behind one guard. `RequireAuth` is a UX control, not
 * security: it stops a user landing on a screen that would 401 and shows them
 * the sign-in page instead. The backend enforces every rule independently.
 *
 * There are no admin-only routes. Two capabilities are administrator-restricted
 * at the backend — confirming what an unrecognised line means, and reading or
 * retiring the vendor packs those confirmations write to. Neither is hidden from
 * the router: each screen reports its own restriction where the operator is
 * standing, rather than presenting a navigation item that leads to a 404.
 */
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

import { EmptyState } from '@/components/ui/States';
import { useAuth } from '@/hooks/useAuth';
import { AppShell } from '@/layouts/AppShell';
import { ActivityPage } from '@/pages/Activity';
import { CompliancePage } from '@/pages/Compliance';
import { DevicesPage } from '@/pages/Devices';
import { LandingPage } from '@/pages/Landing';
import { LoginPage } from '@/pages/Login';
import { RemediationPage } from '@/pages/Remediation';
import { ReportsPage } from '@/pages/Reports';
import { StatusPage } from '@/pages/Status';
import { VendorPacksPage } from '@/pages/VendorPacks';

function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />

      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:deviceId" element={<DevicesPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/remediation" element={<RemediationPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/packs" element={<VendorPacksPage />} />
        <Route path="/activity" element={<ActivityPage />} />
        <Route path="/status" element={<StatusPage />} />

        <Route
          path="*"
          element={
            <div className="card">
              <EmptyState title="Page not found" detail="Open the navigation to pick a section." />
            </div>
          }
        />
      </Route>
    </Routes>
  );
}
