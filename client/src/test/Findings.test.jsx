import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Findings from '../pages/Findings';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    findings: vi.fn().mockResolvedValue({
      findings: [
        {
          _id: 'f1',
          title: 'Missing Content-Security-Policy header',
          severity: 'medium',
          confidence: 'high',
          category: 'headers',
          targetId: 'STATIC_TARGET',
          url: 'https://manikmagar.com.np/',
          method: 'GET',
          parameter: '',
          cwe: 'CWE-693',
          owasp: 'A05:2021',
          description: 'No CSP sent.',
          impact: 'impacts',
          remediation: 'add CSP',
          evidence: { detection_reason: 'header absent' },
          createdAt: '2026-09-05T00:00:00Z',
          detectedAt: '2026-09-05T00:00:00Z',
        },
      ],
    }),
    finding: vi.fn(),
  },
}));

describe('Findings page (§9)', () => {
  it('lists findings and shows filter selects', async () => {
    render(<Findings />);
    await waitFor(() => expect(screen.getByText('Missing Content-Security-Policy header')).toBeInTheDocument());
    // four filters: severity, target, category, confidence (§9) — target is a text input
    expect(screen.getAllByRole('combobox')).toHaveLength(3);
    expect(screen.getByPlaceholderText('target host…')).toBeInTheDocument();
  });

  it('opens a detail dialog with the full finding contract', async () => {
    render(<Findings />);
    await waitFor(() => screen.getByText(/Detail/));
    fireEvent.click(screen.getByText('Detail'));
    expect(screen.getByText('Description')).toBeInTheDocument();
    expect(screen.getByText('No CSP sent.')).toBeInTheDocument();
    expect(screen.getByText('Impact')).toBeInTheDocument();
    expect(screen.getByText('add CSP')).toBeInTheDocument();
    expect(screen.getByText(/CWE-693/)).toBeInTheDocument();
    expect(screen.getByText(/A05:2021/)).toBeInTheDocument();
    expect(screen.getByText(/"detection_reason": "header absent"/)).toBeInTheDocument();
  });
});
