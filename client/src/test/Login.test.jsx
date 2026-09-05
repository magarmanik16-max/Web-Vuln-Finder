import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Login from '../pages/Login';
import { useAuth } from '../context/AuthContext';

vi.mock('../context/AuthContext', () => ({
  useAuth: vi.fn(),
}));

describe('Login page (§16)', () => {
  it('renders email/password form and calls login on submit', async () => {
    const login = vi.fn().mockResolvedValue({ email: 'a@b.c' });
    useAuth.mockReturnValue({ user: null, loading: false, login, logout: vi.fn() });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByPlaceholderText('you@example.local'), { target: { value: 'admin@test.local' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••••••'), { target: { value: 'secret-password' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(login).toHaveBeenCalledWith('admin@test.local', 'secret-password'));
  });

  it('shows the API error message on failed login', async () => {
    const login = vi.fn().mockRejectedValue(new Error('Invalid credentials'));
    useAuth.mockReturnValue({ user: null, loading: false, login, logout: vi.fn() });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByPlaceholderText('you@example.local'), { target: { value: 'x@y.z' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••••••'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(screen.getByText('Invalid credentials')).toBeInTheDocument());
  });
});
