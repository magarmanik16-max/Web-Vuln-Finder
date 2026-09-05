import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Targets from '../pages/Targets';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: { targets: vi.fn() },
}));

describe('Targets page — scope & safety policy', () => {
  beforeEach(() => {
    api.targets.mockResolvedValue({
      policy: {
        statement: 'Any public HTTPS origin may be submitted for assessment, subject to strict URL and network safety validation.',
        requirements: ['HTTPS protocol only', 'Private and loopback ranges are rejected'],
        examples: ['https://manikmagar.com.np', 'https://mnk.manikmagar.com.np'],
      },
    });
  });

  it('describes the safety policy and example targets', async () => {
    render(<Targets />);
    await waitFor(() => expect(screen.getByText(/public HTTPS origin/)).toBeInTheDocument());
    expect(screen.getByText('Validation requirements')).toBeInTheDocument();
    expect(screen.getByText('HTTPS protocol only')).toBeInTheDocument();
    expect(screen.getByText('https://manikmagar.com.np')).toBeInTheDocument();
    expect(screen.getByText('https://mnk.manikmagar.com.np')).toBeInTheDocument();
  });

  it('contains NO input field — scans are started from the Scans page only', () => {
    const { container } = render(<Targets />);
    expect(container.querySelectorAll('input')).toHaveLength(0);
    expect(container.querySelectorAll('textarea')).toHaveLength(0);
  });
});
