import React from 'react';
import { Fingerprint, ShieldAlert, Shield, ShieldCheck, Activity } from 'lucide-react';

import { HeuristicResult } from '@/types';

interface HeuristicReportCardProps {
  // 1. Permitimos que el resultado sea opcional o nulo inicialmente
  result?: HeuristicResult | null; 
}

export default function HeuristicReportCard({ result }: HeuristicReportCardProps) {
  // 2. SALVAGUARDA TEMPRANA: Si no hay datos, no intentamos renderizar
  if (!result) {
    return null; 
    // Opcional: Podrías devolver un <Skeleton /> aquí si quieres un efecto de carga
  }

  // 3. EXTRACCIÓN SEGURA: Valores por defecto por si el backend omite algún campo
  const riskScore = result.risk_score ?? 0;
  const level = result.level || 'LOW';
  const flags = result.flags || []; // Evita el crash al hacer .length o .map

  const getLevelColor = (level: string) => {
    switch (level.toUpperCase()) { // Aseguramos que siempre coincida aunque venga en minúsculas
      case 'CRITICAL': return 'text-red-500 border-red-500/20 bg-red-500/5';
      case 'MEDIUM': return 'text-orange-500 border-orange-500/20 bg-orange-500/5';
      case 'LOW': return 'text-green-500 border-green-500/20 bg-green-500/5';
      default: return 'text-zinc-500 border-zinc-500/20 bg-zinc-500/5';
    }
  };

  const getLevelIcon = (level: string) => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return <ShieldAlert size={18} className="text-red-500" />;
      case 'MEDIUM': return <Shield size={18} className="text-orange-500" />;
      case 'LOW': return <ShieldCheck size={18} className="text-green-500" />;
      default: return <Activity size={18} className="text-zinc-500" />;
    }
  };


  const getLevelLabel = (level: string) => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return 'CRÍTICO';
      case 'MEDIUM': return 'MEDIO';
      case 'LOW': return 'BAJO';
      default: return level;
    }
  };


  return (
    <div className="animate-in fade-in slide-in-from-bottom-2 duration-500">
      <h4 className="text-zinc-100 text-xl font-semibold mb-4 flex items-center space-x-2">
        <span>Análisis Estructural de URL</span>
      </h4>


      <div className="bg-zinc-950 border border-zinc-800 rounded-md p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-center gap-4">

            <div className="relative flex items-center justify-center">
              <svg className="w-16 h-16 transform -rotate-90">
                <circle
                  cx="32"
                  cy="32"
                  r="28"
                  stroke="currentColor"
                  strokeWidth="4"
                  fill="transparent"
                  className="text-zinc-800/50"
                />
                <circle
                  cx="32"
                  cy="32"
                  r="28"
                  stroke="currentColor"
                  strokeWidth="4"
                  fill="transparent"
                  strokeDasharray={175.92}
                  strokeDashoffset={175.92 - (175.92 * riskScore) / 100}
                  className={`${riskScore >= 70 ? 'text-red-500' : riskScore >= 40 ? 'text-orange-500' : 'text-green-500'} transition-all duration-1000 ease-out`}
                />
              </svg>
              <span className="absolute text-sm font-bold text-white">{riskScore}</span>
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                {getLevelIcon(level)}
                <span className={`text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded border ${getLevelColor(level)}`}>
                  Nivel {getLevelLabel(level)}
                </span>
              </div>
              <p className="text-xs text-zinc-400">Puntuación de riesgo estructural</p>
            </div>
          </div>

          
          <div className="hidden md:block h-12 w-[1px] bg-zinc-800"></div>

          <div className="flex-1">
            <p className="text-xs text-zinc-400 mb-2 font-medium uppercase tracking-tight">
              Indicadores Detectados ({flags.length})
            </p>
            <div className="flex flex-wrap gap-2">
              {flags.length > 0 ? (
                flags.map((flag, idx) => (
                  <span key={idx} className="text-[10px] bg-zinc-900 border border-zinc-800 text-zinc-300 px-2 py-1 rounded">
                    {flag}
                  </span>
                ))
              ) : (
                <span className="text-[10px] text-zinc-500 italic">No se detectaron anomalías estructurales significativas.</span>
              )}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}