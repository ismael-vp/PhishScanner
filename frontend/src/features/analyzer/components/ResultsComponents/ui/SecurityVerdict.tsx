import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { ScanResult } from '@/types';

interface SecurityVerdictProps {
  scanResult: ScanResult;
}

export default function SecurityVerdict({ scanResult }: SecurityVerdictProps) {
  const osint = scanResult.osint_data;
  const stats = scanResult.stats;

  const hasAntivirusAlerts = (stats?.malicious || 0) > 0 || (stats?.suspicious || 0) > 0;

  const isDangerous =
    hasAntivirusAlerts ||
    (osint?.abuseConfidenceScore && osint.abuseConfidenceScore > 0) ||
    osint?.is_typosquatting ||
    osint?.has_dangerous_form ||
    osint?.url_anatomy?.hosting_brand_alert ||
    osint?.cloaking_detected;

  let verdictDescription = 'No hemos encontrado problemas de seguridad en este enlace.';

  if (isDangerous) {
    if (hasAntivirusAlerts) {
      verdictDescription = 'Varios motores han detectado problemas en este sitio. Te recomendamos no visitarlo ni compartir datos en\u00A0él.';
    } else if (osint?.cloaking_detected) {
      verdictDescription = 'Hemos detectado técnicas de "Cloaking": el sitio muestra contenido diferente a los sistemas de seguridad que a los usuarios. Señal clara de engaño.';
    } else {
      verdictDescription = 'Hemos encontrado señales de que este sitio intenta engañarte o robar tu información. No introduzcas tus datos.';
    }
  }


  return (
    <div className="animate-in slide-in-from-top-4 duration-700">
      <div className="flex items-center space-x-4 mb-3">
        <div className={`p-2 rounded-xl border ${isDangerous ? 'bg-red-500/5 border-red-500/20' : 'bg-green-500/5 border-green-500/20'}`}>
          {isDangerous ? (
            <ShieldAlert size={32} className="text-red-500" />
          ) : (
            <ShieldCheck size={32} className="text-green-500" />
          )}
        </div>
        <div className="flex flex-col">
          <div className="flex items-center space-x-3">
            <h2 className="text-2xl font-bold text-white tracking-tight">
              {isDangerous ? 'Riesgo Detectado' : 'Sitio Seguro'}
            </h2>
            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase tracking-widest ${isDangerous ? 'text-red-500 border-red-500/20 bg-red-500/10' : 'text-green-500 border-green-500/20 bg-green-500/10'
              }`}>
              {isDangerous ? 'Riesgo Alto' : 'Seguro'}
            </span>
          </div>
          <p className="text-zinc-500 text-sm mt-1">
            Resultado de Seguridad
          </p>
        </div>
      </div>

      <div className="pl-[60px]">
        <p className="text-zinc-400 text-base leading-relaxed">
          {verdictDescription}
        </p>
      </div>
    </div>
  );
}
