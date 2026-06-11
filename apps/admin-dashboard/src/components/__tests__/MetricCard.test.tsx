import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MetricCard } from '../MetricCard';

describe('MetricCard', () => {
  it('renders title', () => {
    render(<MetricCard title="Decisions" value="1,234" change="+12%" trend="up" icon={<span data-testid="icon" />} />);
    expect(screen.getByText('Decisions')).toBeInTheDocument();
  });

  it('renders value', () => {
    render(<MetricCard title="Decisions" value="1,234" change="+12%" trend="up" icon={<span data-testid="icon" />} />);
    expect(screen.getByText('1,234')).toBeInTheDocument();
  });

  it('renders change with up trend', () => {
    render(<MetricCard title="Decisions" value="1,234" change="+12%" trend="up" icon={<span data-testid="icon" />} />);
    expect(screen.getByText('+12%')).toBeInTheDocument();
  });

  it('renders change with down trend', () => {
    render(<MetricCard title="Decisions" value="1,234" change="-5%" trend="down" icon={<span data-testid="icon" />} />);
    expect(screen.getByText('-5%')).toBeInTheDocument();
  });

  it('renders icon', () => {
    render(<MetricCard title="Decisions" value="1,234" change="+12%" trend="up" icon={<span data-testid="icon" />} />);
    expect(screen.getByTestId('icon')).toBeInTheDocument();
  });

  it('applies up trend class for positive change', () => {
    const { container } = render(<MetricCard title="Decisions" value="1,234" change="+12%" trend="up" icon={<span />} />);
    const trendDiv = container.querySelector('[class*="text-green"]');
    expect(trendDiv).toBeTruthy();
  });

  it('applies down trend class for negative change', () => {
    const { container } = render(<MetricCard title="Decisions" value="1,234" change="-5%" trend="down" icon={<span />} />);
    const trendDiv = container.querySelector('[class*="text-red"]');
    expect(trendDiv).toBeTruthy();
  });
});