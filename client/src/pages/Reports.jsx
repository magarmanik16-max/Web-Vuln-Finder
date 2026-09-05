import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Reports() {
  const [reports, setReports] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.reports().then((r) => setReports(r.reports)).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-white">Reports</h1>
      {error && <div className="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-rose-300">{error}</div>}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        {!reports ? (
          <p className="text-sm text-slate-400">Loading…</p>
        ) : reports.length === 0 ? (
          <p className="text-sm text-slate-400">
            No reports yet. Report generation (PDF/HTML from completed scans) is implemented in a later phase; this page and its API exist now.
          </p>
        ) : (
          <ul className="space-y-2 text-sm">
            {reports.map((r) => (
              <li key={r._id} className="flex items-center justify-between rounded-lg bg-slate-950/60 px-3 py-2">
                <span className="font-mono text-xs">{r.scan}</span>
                <span className="text-slate-400">
                  {r.format} · {r.status}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
