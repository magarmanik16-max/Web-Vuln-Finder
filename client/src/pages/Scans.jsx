import { useEffect, useState, useCallback } from 'react';
import { api } from '../lib/api';

export default function Scans() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState(null);
  const [selected, setSelected] = useState('');
  const [message, setMessage] = useState(null);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    try {
      const { scans } = await api.scans();
      setScans(scans);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    api.targets().then((r) => {
      setTargets(r.targets);
      setSelected(r.targets[0]?.id || '');
    });
    refresh();
  }, [refresh]);

  const start = async () => {
    setMessage(null);
    setError('');
    try {
      await api.createScan(selected);
      setMessage({ kind: 'ok', text: `Scan queued for ${selected}. The scanner engine arrives in Phase 2.` });
      await refresh();
    } catch (e) {
      setMessage({ kind: 'err', text: e.message });
    }
  };

  const cancel = async (id) => {
    try {
      await api.cancelScan(id);
      await refresh();
    } catch (e) {
      setMessage({ kind: 'err', text: e.message });
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-white">Scans</h1>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="font-medium text-white">Start a scan</h2>
        <p className="mt-1 text-sm text-slate-400">Pick an authorized target by ID. There is no way to enter a custom URL — by design.</p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-500"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label} ({t.type})
              </option>
            ))}
          </select>
          <button onClick={start} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500">
            Queue scan
          </button>
        </div>
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
                <th className="py-2">Requested by</th>
                <th className="py-2">Created</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s._id} className="border-t border-slate-800">
                  <td className="py-2 font-mono text-xs text-emerald-300">{s.targetId}</td>
                  <td className="py-2">{s.status}</td>
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
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
