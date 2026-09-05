import { useEffect, useState } from 'react';
import { api } from '../lib/api';

/**
 * Describes the target safety policy. There is deliberately NO input here:
 * scans are started from the Scans page by entering a public HTTPS URL,
 * which is validated server-side before anything runs.
 */
export default function Targets() {
  const [policy, setPolicy] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.targets().then((r) => setPolicy(r.policy)).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="rounded-lg border border-rose-800 bg-rose-950/50 px-4 py-3 text-rose-300">{error}</div>;
  if (!policy) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Targets &amp; Scope Policy</h1>
        <p className="mt-1 text-sm text-slate-400">{policy.statement}</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 className="font-medium text-white">Validation requirements</h2>
          <ul className="mt-3 space-y-2 text-sm text-slate-300">
            {policy.requirements.map((r, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-emerald-400">✓</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h2 className="font-medium text-white">Example targets</h2>
          <p className="mt-2 text-sm text-slate-400">These were the platform's original fixed targets — today they are simply valid examples:</p>
          <ul className="mt-3 space-y-2 font-mono text-xs text-emerald-300">
            {policy.examples.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-slate-500">
            Rejected: private/loopback/link-local addresses, non-HTTPS schemes, credentials, explicit ports, unresolvable or non-global
            destinations. Only scan targets you are authorized to assess.
          </p>
        </div>
      </div>
    </div>
  );
}
