import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { ScanResult } from '@/types';

interface SecurityVerdictProps {
  scanResult: ScanResult;
}

export default function SecurityVerdict({ scanResult }: SecurityVerdictProps) {
  const osint = scanResult.osint_data;
  const stats = scanResult.stats;

  const maliciousCount = (stats?.malicious || 0) + (stats?.suspicious || 0);
  const hasAntivirusAlerts = maliciousCount > 0;

  // Un sitio es CRÍTICO (Rojo) si hay más de 2 motores O hay un hallazgo grave (Formulario/Cloaking/Typosquatting)
  const isCritical =
    maliciousCount >= 3 ||
    osint?.has_dangerous_form ||
    osint?.cloaking_detected ||
    osint?.is_typosquatting;

  // Un sitio es SOSPECHOSO (Naranja) si tiene alguna alerta menor
  const isDangerous =
    isCritical ||
    hasAntivirusAlerts ||
    (osint?.abuseConfidenceScore && osint.abuseConfidenceScore >= 25) ||
    osint?.url_anatomy?.hosting_brand_alert;

  let verdictDescription = 'No hemos encontrado problemas de seguridad en este enlace.';

  if (isDangerous) {
    if (osint?.has_dangerous_form) {
      verdictDescription = 'Este sitio contiene un formulario que solicita datos sensibles de forma sospechosa. Es una señal clara de intento de robo de identidad.';
    } else if (osint?.is_typosquatting) {
      verdictDescription = 'Este dominio suplanta la identidad de una marca conocida. Es un sitio falso diseñado para engañarte.';
    } else if (osint?.cloaking_detected) {
      verdictDescription = 'Hemos detectado técnicas de "Cloaking": el sitio intenta ocultar su verdadero contenido. Señal de fraude.';
    } else if (hasAntivirusAlerts) {
      verdictDescription = maliciousCount === 1
        ? 'Un motor de seguridad ha detectado problemas en este sitio. Procede con precaución.'
        : `Un total de ${maliciousCount} motores de seguridad han detectado amenazas en este sitio. Evita visitarlo.`;
    } else {
      verdictDescription = 'Hemos encontrado señales de comportamiento atípico que sugieren que este sitio podría no ser seguro.';
    }
  }

  return (
    <div className="animate-in slide-in-from-top-4 duration-700">
      <div className="flex items-center space-x-4 mb-3">
        <div className={`p-2 rounded-xl border ${isCritical ? 'bg-red-500/5 border-red-500/20' :
            isDangerous ? 'bg-orange-500/5 border-orange-500/20' :
              'bg-green-500/5 border-green-500/20'
          }`}>
          {isCritical ? (
            <ShieldAlert size={32} className="text-red-500" />
          ) : isDangerous ? (
            <ShieldAlert size={32} className="text-orange-500" />
          ) : (
            <ShieldCheck size={32} className="text-green-500" />
          )}
        </div>
        <div className="flex flex-col">
          <div className="flex items-center space-x-3">
            <h2 className="text-2xl font-bold text-white tracking-tight">
              {isCritical ? 'Riesgo Crítico' : isDangerous ? 'Riesgo Detectado' : 'Sitio Seguro'}
            </h2>
            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase tracking-widest ${isCritical ? 'text-red-500 border-red-500/20 bg-red-500/10' :
                isDangerous ? 'text-orange-500 border-orange-500/20 bg-orange-500/10' :
                  'text-green-500 border-green-500/20 bg-green-500/10'
              }`}>
              {isCritical ? 'Riesgo Alto' : isDangerous ? 'Riesgo Medio' : 'Seguro'}
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
