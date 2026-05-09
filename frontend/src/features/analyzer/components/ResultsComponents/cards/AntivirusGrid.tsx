import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ShieldAlert } from 'lucide-react';
import { EngineResult } from '@/types';

interface AntivirusGridProps {
  engines: EngineResult[];
  heuristicFlag?: string;
}

export default function AntivirusGrid({ engines, heuristicFlag }: AntivirusGridProps) {
  const [showAllEngines, setShowAllEngines] = useState(false);

  const ENGINE_STATUS_PRIORITY: Record<string, number> = {
    malicious: 0,
    suspicious: 1,
    harmless: 2,
    clean: 2,
    undetected: 3,
    timeout: 4,
  };

  const sortedEngines = [...engines].sort((a, b) => {
    const pa = ENGINE_STATUS_PRIORITY[a.status] ?? 5;
    const pb = ENGINE_STATUS_PRIORITY[b.status] ?? 5;
    if (pa !== pb) return pa - pb;
    return a.name.localeCompare(b.name);
  });

  return (
    <div>
      <h4 className="text-[#ededed] text-xl font-medium mb-4">Análisis por Motor</h4>

      {heuristicFlag && (
        <div className="mb-4 p-4 rounded-md bg-orange-500/10 border border-orange-500/20 flex items-start space-x-3">
          <ShieldAlert className="text-orange-500 shrink-0 mt-0.5" size={18} />
          <div>
            <h5 className="text-orange-500 font-medium text-sm">Alerta Heurística OSINT (Falso Negativo Evasivo)</h5>
            <p className="text-[#a1a1aa] text-sm mt-1">{heuristicFlag}</p>
          </div>
        </div>
      )}

      <div className={`grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 ${showAllEngines ? 'max-h-[450px] overflow-y-auto pr-2 custom-scrollbar' : ''}`}>
        {(showAllEngines ? sortedEngines : sortedEngines.slice(0, 12)).map((engine, idx) => (
          <div key={idx} className="flex items-center justify-between p-3 sm:p-4 h-14 bg-black border border-[#333] rounded-md overflow-hidden">
            <span className="text-[#ededed] font-medium text-sm truncate mr-3 flex-1 text-left">
              {engine.name}
            </span>
            <div className="flex items-center justify-end gap-1.5 shrink-0 min-w-fit">
              {engine.status === 'malicious' && <div className="w-2 h-2 rounded-full bg-red-500"></div>}
              {engine.status === 'suspicious' && <div className="w-2 h-2 rounded-full bg-orange-500"></div>}
              {engine.status === 'clean' && <div className="w-2 h-2 rounded-full bg-green-500"></div>}
              {engine.status === 'harmless' && <div className="w-2 h-2 rounded-full bg-green-500"></div>}

              <span className={`text-sm capitalize ${engine.status === 'malicious' ? 'text-red-500 font-medium' :
                  engine.status === 'suspicious' ? 'text-orange-500 font-medium' :
                    (engine.status === 'harmless' || engine.status === 'clean') ? 'text-green-500/80' : 'text-[#888]'
                }`}>
                {engine.status === 'harmless' ? 'clean' : engine.status}
              </span>
            </div>
          </div>
        ))}
      </div>

      {sortedEngines.length > 12 && (
        <button
          onClick={() => setShowAllEngines(prev => !prev)}
          className="w-full mt-4 py-2.5 flex items-center justify-center gap-2 text-sm text-[#888] bg-transparent border border-[#333] rounded-md hover:bg-[#111] hover:text-[#ededed] transition-colors cursor-pointer"
        >
          <span className="flex items-center">
            {showAllEngines ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </span>
          <span>
            {showAllEngines ? 'Mostrar menos' : `Ver todos los motores (${sortedEngines.length})`}
          </span>
        </button>
      )}
    </div>
  );
}
