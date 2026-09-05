import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const NAV = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/targets', label: 'Targets' },
  { to: '/scans', label: 'Scans' },
  { to: '/findings', label: 'Findings' },
  { to: '/reports', label: 'Reports' },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-900/60">
        <div className="px-5 py-5">
          <div className="text-lg font-semibold tracking-tight text-white">WebVulnApp</div>
          <div className="text-xs text-slate-400">Authorized Assessment Platform</div>
        </div>
        <nav className="flex-1 space-y-1 px-3">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm ${
                  isActive ? 'bg-emerald-600/20 text-emerald-300' : 'text-slate-300 hover:bg-slate-800'
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 px-5 py-4 text-xs text-slate-400">
          Targets are locked to the
          <br />
          authorized allowlist.
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-slate-800 px-6 py-3">
          <div className="text-sm text-slate-400">Final-year cybersecurity project — Phase 1 foundation</div>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-slate-300">
              {user.name || user.email} <span className="ml-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs text-emerald-300">{user.role}</span>
            </span>
            <button
              onClick={async () => {
                await logout();
                navigate('/login');
              }}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300 hover:bg-slate-800"
            >
              Log out
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
