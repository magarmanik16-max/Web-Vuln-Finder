const COLORS = {
  critical: 'bg-rose-950 text-rose-300 border-rose-800',
  high: 'bg-orange-950 text-orange-300 border-orange-800',
  medium: 'bg-amber-950 text-amber-300 border-amber-800',
  low: 'bg-sky-950 text-sky-300 border-sky-800',
  info: 'bg-slate-800 text-slate-300 border-slate-700',
};

export default function SeverityPill({ severity, count }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs ${COLORS[severity] || COLORS.info}`}>
      {severity}
      {typeof count === 'number' && <span className="font-semibold">{count}</span>}
    </span>
  );
}
