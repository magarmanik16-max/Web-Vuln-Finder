import { useEffect, useState } from 'react';
import { api } from '../lib/api';

/**
 * Targets are immutable platform configuration served by the backend.
 * This page deliberately contains NO input of any kind for URLs —
 * the browser cannot name or influence an assessment destination.
 */
export default function Targets() {
  const [targets, setTargets] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.targets().then((r) => setTargets(r.targets)).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-rose-300">{error}</div>;
  if (!targets) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Targets</h1>
        <p className="mt-1 text-sm text-slate-400">
          The only assets this platform is authorized to assess. The allowlist is enforced server-side; targets cannot be added from here.
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {targets.map((t) => (
          <div key={t.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="font-medium text-white">{t.label}</div>
                <div className="text-xs text-slate-500">{t.id}</div>
              </div>
              <span
                className={`rounded-full border px-2 py-0.5 text-xs ${
                  t.type === 'static' ? 'border-sky-800 bg-sky-950 text-sky-300' : 'border-violet-800 bg-violet-950 text-violet-300'
                }`}
              >
                {t.type}
              </span>
            </div>
            <p className="mt-3 text-sm text-slate-400">{t.description}</p>
            <div className="mt-3 font-mono text-xs text-emerald-300">{t.authorizedUrl}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
