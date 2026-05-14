'use client';

import { useState, useEffect, useRef } from 'react';

type Status = 'checking' | 'online' | 'offline';

const POLL_ONLINE_MS  = 30_000;  // cada 30 s cuando está online
const POLL_OFFLINE_MS = 10_000;  // cada 10 s cuando está offline/checking (cold start Render)
const FETCH_TIMEOUT_MS = 8_000;  // 8 s — Render free tier puede tardar más de 5 s

export default function ServerStatus() {
  const [status, setStatus] = useState<Status>('checking');
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;

    const checkHealth = async () => {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      let next: Status = 'offline';

      try {
        const res = await fetch(`${apiUrl}/health`, {
          method: 'GET',
          cache: 'no-store',
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        next = res.ok ? 'online' : 'offline';
      } catch {
        next = 'offline';
      }

      if (!cancelled) {
        setStatus(next);
        // Si está offline o checking reintenta más rápido para capturar el cold start
        const delay = next === 'online' ? POLL_ONLINE_MS : POLL_OFFLINE_MS;
        timerRef.current = setTimeout(checkHealth, delay);
      }
    };

    checkHealth();

    return () => {
      cancelled = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
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
    offline:  'Servidor offline (despertando…)',
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
