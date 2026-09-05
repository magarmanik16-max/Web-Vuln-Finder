import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Reports() {
  const [reports, setReports] = useState(null);
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState('');
  const [detail, setDetail] = useState(null);
  const [message, setMessage] = useState(null);

  const refresh = () => api.reports().then((r) => setReports(r.reports)).catch((e) => setMessage({ kind: 'err', text: e.message }));

  useEffect(() => {
    refresh();
    api.scans('?status=completed').then((r) => {
      setScans(r.scans);
      if (r.scans[0]) setScanId(r.scans[0]._id);
    });
  }, []);

  const generate = async () => {
    setMessage(null);
    try {
      await api.generateReport(scanId);
      setMessage({ kind: 'ok', text: 'Report generated from stored scan results.' });
      refresh();
    } catch (e) {
      setMessage({ kind: 'err', text: e.message });
    }
  };

  const download = async (id) => {
    try {
      await api.downloadReportPdf(id);
    } catch (e) {
      setMessage({ kind: 'err', text: e.message });
    }
  };

  const s = detail?.sections;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-white">Reports</h1>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="font-medium text-white">Generate a report</h2>
        <p className="mt-1 text-sm text-slate-400">Reports are built strictly from stored scan results — completed or cancelled scans only.</p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <select value={scanId} onChange={(e) => setScanId(e.target.value)} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100">
            {scans.length === 0 && <option value="">No completed scans yet</option>}
            {scans.map((sc) => (
              <option key={sc._id} value={sc._id}>
                {sc.targetId} · {new Date(sc.createdAt).toLocaleString()} · {sc._id.slice(-6)}
              </option>
            ))}
          </select>
          <button onClick={generate} disabled={!scanId} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50">
            Generate PDF report
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
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="font-medium text-white">Report history</h2>
        {!reports ? (
          <p className="mt-2 text-sm text-slate-400">Loading…</p>
        ) : reports.length === 0 ? (
          <p className="mt-2 text-sm text-slate-400">No reports yet.</p>
        ) : (
          <table className="mt-3 w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2">Scan</th>
                <th className="py-2">Target</th>
                <th className="py-2">Format</th>
                <th className="py-2">Status</th>
                <th className="py-2">Created</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r._id} className="border-t border-slate-800">
                  <td className="py-2 font-mono text-xs">{r.scan?._id?.slice(-8) || r.scan?.slice(-8) || '—'}</td>
                  <td className="py-2 font-mono text-xs text-emerald-300">{r.scan?.targetId || '—'}</td>
                  <td className="py-2 text-slate-400">{r.format}</td>
                  <td className="py-2 text-slate-400">{r.status}</td>
                  <td className="py-2 text-slate-400">{new Date(r.createdAt).toLocaleString()}</td>
                  <td className="py-2 space-x-2 text-right">
                    <button onClick={() => api.report(r._id).then((x) => setDetail(x.report))} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
                      View
                    </button>
                    {r.format === 'pdf' && r.status === 'ready' && (
                      <button onClick={() => download(r._id)} className="rounded border border-emerald-800 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-950/40">
                        PDF
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && s && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setDetail(null)}>
          <div className="max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-4">
              <h2 className="text-lg font-semibold text-white">Web Vulnerability Assessment Report</h2>
              <button onClick={() => setDetail(null)} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800">Close</button>
            </div>
            <div className="mt-1 text-xs text-slate-400">
              {s.scope.label} ({s.scope.type}) · Scan {s.riskSummary.scan.id.slice(-8)} · Generated {new Date(s.generatedAt).toLocaleString()}
            </div>

            <ReportSection title="Executive Summary">
              {s.executiveSummary.map((p, i) => (
                <p key={i} className="text-sm text-slate-300">{p}</p>
              ))}
            </ReportSection>
            <ReportSection title="Assessment Scope">
              <p className="text-sm text-slate-300">Target: {s.scope.label} — {s.scope.authorizedUrl} ({s.scope.type})</p>
              <p className="text-sm text-slate-300">{s.scope.assessmentType}</p>
            </ReportSection>
            <ReportSection title="Methodology">
              <ul className="list-disc pl-5 text-sm text-slate-300">
                {s.methodology.map((m, i) => <li key={i}>{m}</li>)}
              </ul>
            </ReportSection>
            <ReportSection title="Risk Summary">
              <p className="text-sm text-slate-300">
                Total: {s.riskSummary.total} (highest: {s.riskSummary.highestSeverity}) — critical {s.riskSummary.counts.critical} · high {s.riskSummary.counts.high} · medium{' '}
                {s.riskSummary.counts.medium} · low {s.riskSummary.counts.low} · informational {s.riskSummary.counts.info}
              </p>
              <p className="text-sm text-slate-400">
                {s.riskSummary.scan.requests} requests · {s.riskSummary.scan.pages} pages · {s.riskSummary.scan.endpoints} endpoints · {s.riskSummary.scan.durationMinutes} min
              </p>
            </ReportSection>
            <ReportSection title={`Findings (${s.findings.length})`}>
              {s.findings.length === 0 && <p className="text-sm text-slate-400">No findings recorded for this scan.</p>}
              {s.findings.map((f, i) => (
                <div key={i} className="mb-3 rounded-lg bg-slate-950/60 p-3">
                  <div className="text-sm font-medium text-white">[{f.severity}] {f.title}</div>
                  <div className="mt-1 text-xs text-slate-400">
                    confidence: {f.confidence} · {f.category}{f.cwe ? ` · ${f.cwe}` : ''}{f.owasp ? ` · ${f.owasp}` : ''}
                  </div>
                  {f.url && <div className="mt-1 font-mono text-xs text-emerald-300 break-all">{f.method} {f.url}</div>}
                  {f.description && <p className="mt-1 text-sm text-slate-300">{f.description}</p>}
                  {f.impact && <p className="mt-1 text-sm text-slate-400">Impact: {f.impact}</p>}
                  {f.remediation && <p className="mt-1 text-sm text-slate-400">Remediation: {f.remediation}</p>}
                </div>
              ))}
            </ReportSection>
            <ReportSection title="Remediation Priorities">
              {s.remediation.length === 0 ? (
                <p className="text-sm text-slate-400">No remediation actions required.</p>
              ) : (
                <ul className="list-disc pl-5 text-sm text-slate-300">
                  {s.remediation.map((r, i) => <li key={i}>[{r.severity}] {r.title}: {r.remediation}</li>)}
                </ul>
              )}
            </ReportSection>
            <ReportSection title="Limitations">
              <ul className="list-disc pl-5 text-sm text-slate-400">
                {s.limitations.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            </ReportSection>
            <div className="mt-4 text-xs text-slate-500">Assessment timestamp: {s.assessmentTimestamp}</div>
          </div>
        </div>
      )}
    </div>
  );
}

function ReportSection({ title, children }) {
  return (
    <div className="mt-5">
      <h3 className="border-b border-slate-800 pb-1 text-sm font-semibold uppercase tracking-wide text-slate-200">{title}</h3>
      <div className="mt-2 space-y-1">{children}</div>
    </div>
  );
}
