'use client';

import { useState, useEffect } from 'react';

type Status = 'checking' | 'online' | 'offline';

export default function ServerStatus() {
  const [status, setStatus] = useState<Status>('checking');

  useEffect(() => {
    const checkServerHealth = async () => {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
        const response = await fetch(`${apiUrl}/api/app-info`, {
          method: 'GET',
          cache: 'no-store',
          signal: AbortSignal.timeout(5000),
        });
        setStatus(response.ok ? 'online' : 'offline');
      } catch {
        setStatus('offline');
      }
    };

    checkServerHealth();
    const intervalId = setInterval(checkServerHealth, 60_000);
    return () => clearInterval(intervalId);
  }, []);

  const ledStyles: Record<Status, string> = {
    checking: 'bg-yellow-400 animate-pulse shadow-[0_0_8px_rgba(250,204,21,0.8)]',
    online:   'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.9)]',
    offline:  'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)]',
  };

  const pingStyles: Record<Status, string> = {
    checking: 'bg-yellow-400 animate-ping',
    online:   'bg-green-400 animate-ping',
    offline:  '',
  };

  const label: Record<Status, string> = {
    checking: 'Verificando servidor…',
    online:   'Servidor online',
    offline:  'Servidor offline',
  };

  return (
    <div
      className="fixed top-5 right-6 flex h-2 w-2 items-center justify-center z-50"
      title={label[status]}
      aria-label={label[status]}
    >
      {status !== 'offline' && (
        <span className={`absolute inline-flex h-full w-full rounded-full opacity-40 ${pingStyles[status]}`} />
      )}
      <span className={`relative inline-flex rounded-full h-2 w-2 ${ledStyles[status]}`} />
    </div>
  );
}
