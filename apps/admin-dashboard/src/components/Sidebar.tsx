'use client';

import { Shield, Activity, FileText, Layers, Search, Settings, Users } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import clsx from 'clsx';

const navItems = [
  { href: '/', label: 'Dashboard', icon: Activity },
  { href: '/gateways', label: 'Gateways', icon: Shield },
  { href: '/policies', label: 'Policies', icon: FileText },
  { href: '/audit-log', label: 'Audit Log', icon: Search },
  { href: '/organizations', label: 'Organizations', icon: Users },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-surface border-r border-surface-border flex flex-col min-h-screen">
      <div className="p-6 border-b border-surface-border">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-ovara-500" />
          <div>
            <h1 className="text-xl font-bold text-white">Ovara</h1>
            <p className="text-xs text-slate-400">Control Plane</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-ovara-900/30 text-ovara-400 border border-ovara-800/50'
                  : 'text-slate-400 hover:text-white hover:bg-surface-lighter'
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-surface-border">
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="h-8 w-8 rounded-full bg-ovara-900 flex items-center justify-center">
            <span className="text-xs font-bold text-ovara-400">AD</span>
          </div>
          <div>
            <p className="text-sm font-medium text-white">Admin</p>
            <p className="text-xs text-slate-400">admin@ovara.dev</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
