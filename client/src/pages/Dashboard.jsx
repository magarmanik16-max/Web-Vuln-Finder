import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import SeverityPill from '../components/SeverityPill';
import { StatusBadge } from './Scans';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const [targets, scans, findings] = await Promise.all([api.targets(), api.scans(), api.findings()]);
        setData({ targets: targets.targets, scans: scans.scans, findings: findings.findings });
      } catch (e) {
        setError(e.message);
      }
    })();
  }, []);

  if (error) return <div className="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-rose-300">{error}</div>;
  if (!data) return <div className="text-slate-400">Loading…</div>;

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of data.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const active = data.scans.filter((s) => ['queued', 'running'].includes(s.status)).length;
  const completed = data.scans.filter((s) => s.status === 'completed').length;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-white">Security Dashboard</h1>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Authorized targets" value={data.targets.length} hint="Immutable allowlist" />
        <StatCard label="Scans" value={data.scans.length} hint={`${active} active · ${completed} completed`} />
        <StatCard label="Total findings" value={data.findings.length} hint="Across all scans" />
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm text-slate-400">Severity distribution</div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {Object.entries(counts).map(([sev, n]) => (
              <SeverityPill key={sev} severity={sev} count={n} />
            ))}
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 className="font-medium text-white">Recent scans</h2>
          {data.scans.length === 0 ? (
            <p className="mt-2 text-sm text-slate-400">No scans yet. Start one from the Scans page — only authorized targets are offered.</p>
          ) : (
            <ul className="mt-3 space-y-2 text-sm">
              {data.scans.slice(0, 5).map((s) => {
                const total = Object.values(s.summary || {}).reduce((a, b) => a + b, 0);
                return (
                  <li key={s._id} className="flex items-center justify-between rounded-lg bg-slate-950/60 px-3 py-2">
                    <span className="font-mono text-xs text-emerald-300">{s.targetId}</span>
                    <span className="flex items-center gap-3 text-slate-400">
                      <span>{total} findings</span>
                      {s.durationMs ? <span>{Math.round(s.durationMs / 1000)}s</span> : null}
                      <StatusBadge status={s.status} />
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 className="font-medium text-white">Recent findings</h2>
          {data.findings.length === 0 ? (
            <p className="mt-2 text-sm text-slate-400">No findings yet — they appear here as scans complete.</p>
          ) : (
            <ul className="mt-3 space-y-2 text-sm">
              {data.findings.slice(0, 5).map((f) => (
                <li key={f._id} className="flex items-center justify-between gap-3 rounded-lg bg-slate-950/60 px-3 py-2">
                  <span className="truncate text-slate-300">{f.title}</span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className="font-mono text-xs text-emerald-300">{f.targetId}</span>
                    <SeverityPill severity={f.severity} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, hint }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="mt-1 text-3xl font-semibold text-white">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{hint}</div>
    </div>
  );
}
