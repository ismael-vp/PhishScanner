"use client";

import React, { useEffect, useState } from 'react';
import { useThreatStore } from '@/store/useThreatStore';
import { Clock, ShieldAlert, CheckCircle, Trash2 } from 'lucide-react';

export default function HistoryPanel() {
  const { history, clearHistory, setScanResult, setMode } = useThreatStore();
  // Zustand persist hydration hydration fix
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMounted(true);
  }, []);

  if (!mounted || history.length === 0) return null;

  return (
    <div className="w-full max-w-5xl mx-auto mt-12 animate-in fade-in duration-500 pt-8 border-t border-[#333]">
      <div className="flex items-center justify-between mb-6 px-1">
        <h3 className="text-sm font-medium text-[#ededed] flex items-center space-x-2">
          <Clock size={16} className="text-[#888]" />
          <span>Escaneos Recientes</span>
        </h3>
        <button 
          onClick={clearHistory}
          className="text-sm text-[#888] hover:text-red-500 transition-colors flex items-center space-x-1"
        >
          <Trash2 size={14} />
          <span>Limpiar historial</span>
        </button>
      </div>
      
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {history.map((item, idx) => {
          const isMalicious = (item.stats?.malicious ?? 0) > 0 || (item.stats?.suspicious ?? 0) > 0;
          return (
            <div 
              key={`${item.resourceName}-${idx}`} 
              onClick={() => {
                setMode(item.type);
                // Cargar el resultado guardado y actualizar la UI
                setScanResult(item, item.resourceName);
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }}
              className="bg-black border border-[#333] p-4 rounded-lg cursor-pointer hover:border-[#555] hover:bg-[#111] transition-all group"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center space-x-1.5">
                  {isMalicious ? (
                    <ShieldAlert size={14} className="text-red-600" />
                  ) : (
                    <CheckCircle size={14} className="text-green-500" />
                  )}
                  <span className={`text-[10px] uppercase font-bold tracking-wider ${isMalicious ? 'text-red-600' : 'text-green-500'}`}>
                    {isMalicious ? 'Threat' : 'Clean'}
                  </span>
                </div>
                <span className="text-[11px] text-[#888]">
                  {item.timestamp ? new Date(item.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : ''}
                </span>
              </div>
              <div className="text-sm text-[#ededed] font-medium truncate mb-1">
                {item.resourceName || 'Recurso Desconocido'}
              </div>
              <div className="text-xs text-[#888] capitalize">
                Tipo: {item.type}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
