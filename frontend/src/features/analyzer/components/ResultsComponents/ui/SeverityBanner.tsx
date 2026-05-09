import React from 'react';
import { ShieldAlert, CheckCircle } from 'lucide-react';

interface SeverityBannerProps {
  isMalicious: boolean;
  maliciousCount: number;
  totalEngines: number;
}

export default function SeverityBanner({ isMalicious, maliciousCount, totalEngines }: SeverityBannerProps) {
  const percentMalicious = totalEngines > 0 ? (maliciousCount / totalEngines) * 100 : 0;
  const percentClean = 100 - percentMalicious;

  return (
    <div
      className={`p-6 rounded-lg flex flex-col border ${
        isMalicious ? 'border-red-900/50 bg-[#1a0505]' : 'border-[#333] bg-black'
      }`}
    >
      <div className="flex items-center space-x-4">
        {isMalicious ? (
          <ShieldAlert className="text-red-600 flex-shrink-0" size={24} />
        ) : (
          <CheckCircle className="text-[#ededed] flex-shrink-0" size={24} />
        )}
        <div className="flex-1">
          <h3 className={`text-base font-semibold ${isMalicious ? 'text-red-600' : 'text-[#ededed]'}`}>
            {isMalicious ? 'Alertas de Antivirus' : 'Análisis Limpio'}
          </h3>
          <p className="text-sm text-[#888] mt-1">
            {isMalicious
              ? `${maliciousCount} de ${totalEngines} motores han emitido una alerta.`
              : `Todos los motores operativos reportan este sitio como seguro.`}
          </p>
        </div>
      </div>

      <div className="mt-4 w-full bg-[#222] h-1.5 rounded-full overflow-hidden flex">
        {isMalicious ? (
          <>
            <div style={{ width: `${percentMalicious}%` }} className="bg-red-600 h-full transition-all duration-1000"></div>
            <div style={{ width: `${percentClean}%` }} className="bg-[#333] h-full transition-all duration-1000"></div>
          </>
        ) : (
          <div className="w-full bg-green-500 h-full transition-all duration-1000"></div>
        )}
      </div>
    </div>
  );
}
