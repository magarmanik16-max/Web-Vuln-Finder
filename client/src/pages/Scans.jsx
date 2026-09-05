import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../lib/api';

const MODULE_LABELS = {
  authorization: 'Authorization',
  connectivity: 'Connectivity',
  crawl: 'Crawler',
  headers: 'Headers',
  tls: 'TLS',
  cookies: 'Cookies',
  cors: 'CORS',
  methods: 'HTTP Methods',
  disclosure: 'Info Disclosure',
  xss: 'XSS',
  sqli: 'SQL Injection',
  csrf: 'CSRF',
};

const STATUS_COLORS = {
  queued: 'bg-amber-950 text-amber-300 border-amber-800',
  running: 'bg-sky-950 text-sky-300 border-sky-800',
  completed: 'bg-emerald-950 text-emerald-300 border-emerald-800',
  cancelled: 'bg-slate-800 text-slate-300 border-slate-700',
  failed: 'bg-rose-950 text-rose-300 border-rose-800',
};

function StatusBadge({ status }) {
  return <span className={`rounded-full border px-2 py-0.5 text-xs ${STATUS_COLORS[status] || STATUS_COLORS.cancelled}`}>{status}</span>;
}

function ProgressChecklist({ scan }) {
  const modules = scan.progress?.modules || {};
  const current = scan.progress?.currentModule || '';
  const order = Object.keys(MODULE_LABELS);
  return (
    <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-3">
      {order.map((m) => {
        const state = modules[m] || (current === m ? 'running' : 'pending');
        const mark = state === 'done' ? '✓' : state === 'running' ? '→' : '○';
        return (
          <div key={m} className={`flex items-center justify-between rounded px-2 py-1 ${state === 'running' ? 'bg-sky-950/40' : ''}`}>
            <span className="text-slate-300">{MODULE_LABELS[m]}</span>
            <span className={state === 'done' ? 'text-emerald-400' : state === 'running' ? 'text-sky-300' : 'text-slate-600'}>{mark}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function Scans() {
  const [scans, setScans] = useState(null);
  const [url, setUrl] = useState('');
  const [message, setMessage] = useState(null);
  const [error, setError] = useState('');
  const pollRef = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const { scans } = await api.scans();
      setScans(scans);
      return scans;
    } catch (e) {
      setError(e.message);
      return [];
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Poll while any scan is queued/running (simplest reliable progress mechanism).
  useEffect(() => {
    pollRef.current = setInterval(async () => {
      if (scans && scans.some((s) => ['queued', 'running'].includes(s.status))) refresh();
    }, 2000);
    return () => clearInterval(pollRef.current);
  }, [scans, refresh]);

  const start = async (e) => {
    e.preventDefault();
    setMessage(null);
    setError('');
    try {
      await api.createScan(url);
      setMessage({ kind: 'ok', text: `Scan queued for ${url}.` });
      setUrl('');
      await refresh();
    } catch (err) {
      setMessage({ kind: 'err', text: err.message });
    }
  };

  const cancel = async (id) => {
    setMessage(null);
    try {
      await api.cancelScan(id);
      setMessage({ kind: 'ok', text: 'Cancellation requested — partial findings will be preserved.' });
      await refresh();
    } catch (e) {
      setMessage({ kind: 'err', text: e.message });
    }
  };

  const active = scans?.filter((s) => ['queued', 'running'].includes(s.status)) || [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-white">Scans</h1>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="font-medium text-white">Start a scan</h2>
        <p className="mt-1 text-sm text-slate-400">
          Enter a public HTTPS origin to assess. Private, loopback and otherwise unsafe destinations are rejected server-side; redirects and
          crawling stay on the scanned origin.
        </p>
        <form onSubmit={start} className="mt-4 flex flex-wrap items-center gap-3">
          <input
            type="url"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-80 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-500"
          />
          <button type="submit" className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500">
            Start scan
          </button>
        </form>
        {message && (
          <div
            className={`mt-3 rounded-lg border px-3 py-2 text-sm ${
              message.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/50 text-rose-300'
            }`}
          >
            {message.text}
          </div>
        )}
        {error && <div className="mt-3 rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-sm text-rose-300">{error}</div>}
      </div>

      {active.map((scan) => (
        <div key={scan._id} className="rounded-xl border border-sky-900 bg-slate-900/70 p-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-3">
              <h2 className="font-medium text-white">Live scan — {scan.targetUrl || scan.targetId}</h2>
              <StatusBadge status={scan.status} />
            </div>
            <button onClick={() => cancel(scan._id)} className="rounded border border-rose-800 px-3 py-1.5 text-xs text-rose-300 hover:bg-rose-950/50">
              Cancel scan
            </button>
          </div>
          <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-400">
            <span>Module: {scan.progress?.currentModule || 'starting…'}</span>
            <span>Requests: {scan.progress?.requests ?? 0}</span>
            <span>Pages: {scan.progress?.pages ?? 0}</span>
            <span>Endpoints: {scan.progress?.endpoints ?? 0}</span>
            <span>Duration: {scan.startedAt ? Math.round((Date.now() - new Date(scan.startedAt)) / 1000) : 0}s</span>
          </div>
          <ProgressChecklist scan={scan} />
        </div>
      ))}

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="font-medium text-white">Scan history</h2>
        {!scans ? (
          <p className="mt-2 text-sm text-slate-400">Loading…</p>
        ) : scans.length === 0 ? (
          <p className="mt-2 text-sm text-slate-400">No scans yet.</p>
        ) : (
          <table className="mt-3 w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2">Target</th>
                <th className="py-2">Status</th>
                <th className="py-2">Findings</th>
                <th className="py-2">Duration</th>
                <th className="py-2">Requested by</th>
                <th className="py-2">Created</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => {
                const total = Object.values(s.summary || {}).reduce((a, b) => a + b, 0);
                return (
                  <tr key={s._id} className="border-t border-slate-800">
                    <td className="py-2 font-mono text-xs text-emerald-300">{s.targetUrl || s.targetId}</td>
                    <td className="py-2">
                      <StatusBadge status={s.status} />
                    </td>
                    <td className="py-2">{total}</td>
                    <td className="py-2 text-slate-400">{s.durationMs ? `${Math.round(s.durationMs / 1000)}s` : '—'}</td>
                    <td className="py-2 text-slate-400">{s.requestedBy?.email || '—'}</td>
                    <td className="py-2 text-slate-400">{new Date(s.createdAt).toLocaleString()}</td>
                    <td className="py-2 text-right">
                      {['queued', 'running'].includes(s.status) && (
                        <button onClick={() => cancel(s._id)} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
                          Cancel
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export { StatusBadge };
