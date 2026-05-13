'use client';

import { useState, useEffect } from 'react';

export default function ServerStatus() {
  const [status, setStatus] = useState<'checking' | 'online' | 'offline'>('checking');

  useEffect(() => {
    const checkServerHealth = async () => {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
        
        const response = await fetch(`${apiUrl}/health`, { 
          method: 'GET',
          signal: AbortSignal.timeout(3000) 
        });

        if (response.ok) {
          setStatus('online');
        } else {
          setStatus('offline');
        }
      } catch (error) {
        setStatus('offline');
      }
    };

    checkServerHealth();
    const intervalId = setInterval(checkServerHealth, 30000);

    return () => clearInterval(intervalId);
  }, []);

  const ledStyles = {
    checking: 'bg-yellow-400 animate-pulse shadow-[0_0_8px_rgba(250,204,21,0.8)]',
    online: 'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.9)]',
    offline: 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)]',
  };

  return (
    <div 
      className="fixed top-5 right-6 flex h-2 w-2 items-center justify-center z-50"
      title={`Backend: ${status}`}
    >
      {/* Efecto de onda (ping) */}
      {status !== 'offline' && (
        <span className={`absolute inline-flex h-full w-full rounded-full opacity-40 ${status === 'online' ? 'bg-green-400 animate-ping' : 'bg-yellow-400'}`}></span>
      )}
      {/* Núcleo del LED */}
      <span className={`relative inline-flex rounded-full h-2 w-2 ${ledStyles[status]}`}></span>
    </div>
  );
}
