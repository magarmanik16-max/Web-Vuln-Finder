import { useEffect, useState, useCallback } from 'react';
import { api } from '../lib/api';
import SeverityPill from '../components/SeverityPill';

const SELECT_CLASS = 'rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100';

export default function Findings() {
  const [findings, setFindings] = useState(null);
  const [filters, setFilters] = useState({ severity: '', targetId: '', category: '', confidence: '' });
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
    try {
      const r = await api.findings(qs ? `?${qs}` : '');
      setFindings(r.findings);
    } catch (e) {
      setError(e.message);
    }
  }, [filters]);

  useEffect(() => {
    load();
  }, [load]);

  const set = (k) => (e) => setFilters((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold text-white">Findings</h1>
        <div className="flex flex-wrap gap-2">
          <select value={filters.severity} onChange={set('severity')} className={SELECT_CLASS}>
            <option value="">All severities</option>
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={filters.targetId} onChange={set('targetId')} className={SELECT_CLASS}>
            <option value="">All targets</option>
            <option value="STATIC_TARGET">STATIC_TARGET</option>
            <option value="DYNAMIC_TARGET">DYNAMIC_TARGET</option>
          </select>
          <select value={filters.category} onChange={set('category')} className={SELECT_CLASS}>
            <option value="">All categories</option>
            {['headers', 'tls', 'cookies', 'cors', 'methods', 'disclosure', 'xss', 'sqli', 'csrf'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={filters.confidence} onChange={set('confidence')} className={SELECT_CLASS}>
            <option value="">All confidence</option>
            {['high', 'medium', 'low'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>
      {error && <div className="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-rose-300">{error}</div>}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        {!findings ? (
          <p className="text-sm text-slate-400">Loading…</p>
        ) : findings.length === 0 ? (
          <p className="text-sm text-slate-400">No findings match the current filters.</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2">Severity</th>
                <th className="py-2">Title</th>
                <th className="py-2">Category</th>
                <th className="py-2">Confidence</th>
                <th className="py-2">Target</th>
                <th className="py-2"></th>
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
                  <td className="py-2 text-slate-400">{f.confidence}</td>
                  <td className="py-2 font-mono text-xs text-emerald-300">{f.targetId}</td>
                  <td className="py-2 text-right">
                    <button onClick={() => setDetail(f)} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
                      Detail
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setDetail(null)}>
          <div className="max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-4">
              <h2 className="text-lg font-semibold text-white">{detail.title}</h2>
              <button onClick={() => setDetail(null)} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800">Close</button>
            </div>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <SeverityPill severity={detail.severity} />
              <span className="rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-slate-300">confidence: {detail.confidence}</span>
              <span className="rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-slate-300">{detail.category}</span>
              {detail.cwe && <span className="rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-slate-300">{detail.cwe}</span>}
              {detail.owasp && <span className="rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-slate-300">{detail.owasp}</span>}
            </div>
            {detail.url && (
              <div className="mt-4 rounded-lg bg-slate-950/70 p-3 font-mono text-xs text-emerald-300 break-all">
                {detail.method} {detail.url}
                {detail.parameter && <span className="text-slate-400"> · parameter: {detail.parameter}</span>}
              </div>
            )}
            {detail.description && <Section title="Description" body={detail.description} />}
            {detail.impact && <Section title="Impact" body={detail.impact} />}
            {detail.remediation && <Section title="Remediation" body={detail.remediation} />}
            {detail.evidence && Object.keys(detail.evidence).length > 0 && (
              <Section title="Evidence" body={JSON.stringify(detail.evidence, null, 2)} mono />
            )}
            <div className="mt-4 text-xs text-slate-500">
              Detected: {new Date(detail.detectedAt || detail.createdAt).toLocaleString()} · Module: {detail.scannerModule || '—'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ title, body, mono }) {
  return (
    <div className="mt-4">
      <h3 className="text-sm font-medium text-slate-300">{title}</h3>
      <p className={`mt-1 whitespace-pre-wrap rounded-lg bg-slate-950/60 p-3 text-sm text-slate-300 ${mono ? 'font-mono text-xs break-all' : ''}`}>{body}</p>
    </div>
  );
}
