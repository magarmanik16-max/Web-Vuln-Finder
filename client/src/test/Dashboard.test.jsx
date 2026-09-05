import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Dashboard from '../pages/Dashboard';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    targets: vi.fn().mockResolvedValue({ targets: [{ id: 'STATIC_TARGET' }, { id: 'DYNAMIC_TARGET' }] }),
    scans: vi.fn().mockResolvedValue({
      scans: [
        { _id: 's1', targetId: 'STATIC_TARGET', status: 'completed', summary: { high: 2, info: 1 }, durationMs: 34000 },
        { _id: 's2', targetId: 'DYNAMIC_TARGET', status: 'running', summary: {}, durationMs: 0 },
      ],
    }),
    findings: vi.fn().mockResolvedValue({
      findings: [
        { _id: 'f1', title: 'Missing CSP', severity: 'medium', targetId: 'STATIC_TARGET' },
        { _id: 'f2', title: 'Missing HSTS', severity: 'low', targetId: 'STATIC_TARGET' },
      ],
    }),
  },
}));

describe('Dashboard (§7)', () => {
  it('shows scan/finding statistics and recent activity', async () => {
    render(<Dashboard />);
    await waitFor(() => expect(screen.getByText('Security Dashboard')).toBeInTheDocument());
    expect(screen.getAllByText('2').length).toBeGreaterThanOrEqual(1); // targets + scans stat cards
    expect(screen.getByText('1 active · 1 completed')).toBeInTheDocument();
    expect(screen.getByText('Across all scans')).toBeInTheDocument();
    expect(screen.getByText('Recent scans')).toBeInTheDocument();
    expect(screen.getByText('Recent findings')).toBeInTheDocument();
    expect(screen.getByText('Missing CSP')).toBeInTheDocument();
    expect(screen.getByText('34s')).toBeInTheDocument(); // duration of completed scan
  });
});
