/**
 * A containment boundary for render-time failures.
 *
 * React 18 unmounts the **entire root** when a render throws and nothing
 * catches it, so a single wrong assumption about a response shape turns the
 * whole application into a white page. That is the least diagnosable failure
 * this interface can produce: an operator cannot tell it from a dead server, a
 * bad session or an empty fleet, and DEVELOPER_GUIDE.md §14 is explicit that a failure
 * must raise rather than degrade into something indistinguishable from a clean
 * result.
 *
 * So a panel that throws reports that it threw, names the error, and leaves the
 * rest of the screen usable. It is deliberately not styled as an empty state or
 * an abstention: nothing was evaluated here and nothing is being claimed — the
 * interface is broken, and it says so.
 */
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  /** What failed, in the operator's terms: "The remediation panel". */
  label: string;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Kept in the console for whoever is debugging; never swallowed.
    console.error(`${this.props.label} failed to render`, error, info.componentStack);
  }

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="px-5 py-6" role="alert">
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-fail" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <p className="font-medium text-ink">{this.props.label} could not be displayed</p>
            <p className="mt-1 text-ink-2">
              This is a fault in the interface, not a result from the engine. Nothing here should
              be read as a finding.
            </p>
            <p className="mono mt-2 break-words text-muted">{error.message}</p>
            <button
              type="button"
              onClick={() => this.setState({ error: null })}
              className="mt-3 inline-flex items-center gap-1.5 text-accent hover:underline
                         underline-offset-2"
            >
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              Try again
            </button>
          </div>
        </div>
      </div>
    );
  }
}
