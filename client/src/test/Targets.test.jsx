import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Targets from '../pages/Targets';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: { targets: vi.fn() },
}));

describe('Targets page (§8)', () => {
  beforeEach(() => {
    api.targets.mockResolvedValue({
      targets: [
        { id: 'STATIC_TARGET', label: 'manikmagar.com.np', host: 'manikmagar.com.np', type: 'static', description: 'Static target', authorizedUrl: 'https://manikmagar.com.np' },
        { id: 'DYNAMIC_TARGET', label: 'mnk.manikmagar.com.np', host: 'mnk.manikmagar.com.np', type: 'dynamic', description: 'Dynamic target', authorizedUrl: 'https://mnk.manikmagar.com.np' },
      ],
    });
  });

  it('shows exactly the two authorized targets', async () => {
    render(<Targets />);
    await waitFor(() => expect(screen.getByText('manikmagar.com.np')).toBeInTheDocument());
    expect(screen.getByText('mnk.manikmagar.com.np')).toBeInTheDocument();
    expect(screen.getByText('STATIC_TARGET')).toBeInTheDocument();
    expect(screen.getByText('DYNAMIC_TARGET')).toBeInTheDocument();
    expect(screen.getByText('static')).toBeInTheDocument();
    expect(screen.getByText('dynamic')).toBeInTheDocument();
  });

  it('contains NO input field — the browser cannot name a target (§8)', () => {
    const { container } = render(<Targets />);
    expect(container.querySelectorAll('input')).toHaveLength(0);
    expect(container.querySelectorAll('textarea')).toHaveLength(0);
  });
});
