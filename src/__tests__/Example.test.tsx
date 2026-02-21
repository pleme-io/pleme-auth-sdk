import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { Example } from '../Example';

describe('Example', () => {
  it('renders with default title', () => {
    render(<Example />);
    expect(screen.getByText('Example Component')).toBeInTheDocument();
  });

  it('renders with custom title', () => {
    render(<Example title="Custom Title" />);
    expect(screen.getByText('Custom Title')).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const handleClick = vi.fn();
    render(<Example onClick={handleClick} />);

    fireEvent.click(screen.getByText('Example Component'));

    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('forwards ref correctly', () => {
    const ref = { current: null };
    render(<Example ref={ref} />);

    expect(ref.current).toBeInstanceOf(HTMLDivElement);
  });
});
