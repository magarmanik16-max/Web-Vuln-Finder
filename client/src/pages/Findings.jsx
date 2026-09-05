import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import SeverityPill from '../components/SeverityPill';

export default function Findings() {
  const [findings, setFindings] = useState(null);
  const [severity, setSeverity] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const qs = severity ? `?severity=${severity}` : '';
    api.findings(qs).then((r) => setFindings(r.findings)).catch((e) => setError(e.message));
  }, [severity]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-white">Findings</h1>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
        >
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      {error && <div className="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-rose-300">{error}</div>}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        {!findings ? (
          <p className="text-sm text-slate-400">Loading…</p>
        ) : findings.length === 0 ? (
          <p className="text-sm text-slate-400">No findings yet — the scanner engine is implemented in Phase 2.</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2">Severity</th>
                <th className="py-2">Title</th>
                <th className="py-2">Category</th>
                <th className="py-2">Target</th>
                <th className="py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f._id} className="border-t border-slate-800">
                  <td className="py-2">
                    <SeverityPill severity={f.severity} />
                  </td>
                  <td className="py-2">{f.title}</td>
                  <td className="py-2 text-slate-400">{f.category}</td>
                  <td className="py-2 font-mono text-xs text-emerald-300">{f.targetId}</td>
                  <td className="py-2 text-slate-400">{f.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
