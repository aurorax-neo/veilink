import { ConsoleProvider, useConsole } from './context/ConsoleContext'
import { AppShell } from './components/AppShell'
import { SetupView } from './views/SetupView'
import { LoginView } from './views/LoginView'
import { DashboardView } from './views/DashboardView'
import { NodesView } from './views/NodesView'
import { ProxiesView } from './views/ProxiesView'
import { LogsView } from './views/LogsView'
import { AuditView } from './views/AuditView'
import { SettingsView } from './views/SettingsView'

function RouterView() {
  const { phase, page, dict } = useConsole()

  return (
    <>
      <a className="skip-link" href={phase === 'app' ? '#main' : '#login-main'}>
        {dict.common.skipToMain}
      </a>

      {phase === 'boot' ? (
        <div className="app-shell" aria-hidden="true">
          <aside className="app-sidebar">
            <div style={{ display: 'grid', gap: 10, padding: 8 }}>
              <div style={{ height: 34, borderRadius: 8, background: 'var(--surface-3)' }} />
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} style={{ height: 36, borderRadius: 8, background: 'var(--surface-2)' }} />
              ))}
            </div>
          </aside>
          <div className="app-workspace">
            <div className="app-topbar" />
            <div className="app-stage">
              <div className="stage-inner">
                <div style={{ height: 34, width: 220, borderRadius: 8, background: 'var(--surface-2)' }} />
                <div className="kpi-grid">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} style={{ height: 104, borderRadius: 16, background: 'var(--surface-2)' }} />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : phase === 'setup' ? (
        <SetupView />
      ) : phase === 'login' ? (
        <LoginView />
      ) : (
        <AppShell>
          {page === 'dashboard' && <DashboardView />}
          {page === 'servers' && <NodesView role="server" />}
          {page === 'clients' && <NodesView role="client" />}
          {page === 'proxies' && <ProxiesView />}
          {page === 'logs' && <LogsView />}
          {page === 'audit' && <AuditView />}
          {page === 'settings' && <SettingsView />}
        </AppShell>
      )}
    </>
  )
}

export default function App() {
  return (
    <ConsoleProvider>
      <RouterView />
    </ConsoleProvider>
  )
}
