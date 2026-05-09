import React from 'react';
import { OSINTData } from '@/types';

const getFlagEmoji = (countryCode?: string) => {
  if (!countryCode) return '';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};

interface UrlMetadataCardProps {
  resourceName?: string;
  isMalicious: boolean;
  osintData?: OSINTData | null;
}

export default function UrlMetadataCard({ resourceName, isMalicious, osintData }: UrlMetadataCardProps) {
  return (
    <div>
      <h4 className="text-[#ededed] text-xl font-medium mb-4">Metadatos</h4>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 p-8 border border-[#333] rounded-md bg-[#050505] mb-8">
        
        {/* Recurso Analizado + Defanging */}
        <div className="flex flex-col space-y-2 col-span-1 md:col-span-2">
          <span className="text-sm text-[#888]">Recurso Analizado</span>
          <div className="flex items-center space-x-4">
            <span className="text-base text-[#ededed] font-medium font-mono truncate max-w-[300px] md:max-w-md">
              {resourceName || '-'}
            </span>
            <button
              onClick={() => {
                if (resourceName) {
                  const defanged = resourceName.replace(/http/gi, 'hxxp').replace(/\./g, '[.]');
                  navigator.clipboard.writeText(defanged);
                  alert("URL segura copiada al portapapeles: " + defanged);
                }
              }}
              className="text-xs uppercase font-bold px-3 py-1.5 bg-[#111] hover:bg-[#222] text-[#ededed] rounded transition-colors border border-[#333]"
            >
              Copiar Defanged
            </button>
          </div>
        </div>

        {/* Categoría */}
        <div className="flex flex-col space-y-2 justify-center">
          <span className="text-sm text-[#888]">Categoría Primaria</span>
          <span className="text-base text-[#ededed] font-medium">
            {isMalicious ? 'Phishing / Malware' : 'Benigno'}
          </span>
        </div>

        {/* IP y Geolocalización */}
        <div className="flex flex-col space-y-2 justify-center">
          <span className="text-sm text-[#888]">Resolución / IP</span>
          {osintData?.geolocation ? (
            <div className="flex flex-col space-y-1">
              <span className="text-base text-[#ededed] font-medium font-mono">
                {osintData.geolocation.ip}
              </span>
              <span className="text-xs text-[#888] truncate max-w-[200px]" title={`${osintData.geolocation.country} - ${osintData.geolocation.isp}`}>
                {getFlagEmoji(osintData.geolocation.countryCode)} {osintData.geolocation.isp}
              </span>
            </div>
          ) : (
            <span className="text-base text-[#ededed] font-medium font-mono">
              Desconocida
            </span>
          )}
        </div>

        {/* Reputación IP */}
        {osintData?.abuseConfidenceScore !== undefined && osintData.abuseConfidenceScore !== null && (
          <div className="flex flex-col space-y-2 justify-center">
            <span className="text-sm text-[#888]">Reputación IP (AbuseIPDB)</span>
            <div className="flex items-center space-x-2">
              {osintData.abuseConfidenceScore === 0 ? (
                <span className="text-base text-[#ededed] font-medium">0% (Limpia)</span>
              ) : osintData.abuseConfidenceScore > 50 ? (
                <div className="flex items-center space-x-2">
                  <span className="text-base text-red-500 font-medium">{osintData.abuseConfidenceScore}%</span>
                  <span className="bg-red-900/50 text-red-500 text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border border-red-800">Maliciosa</span>
                </div>
              ) : (
                <span className="text-base text-yellow-500 font-medium">{osintData.abuseConfidenceScore}%</span>
              )}
              <span className="text-xs text-[#666]">({osintData.totalReports || 0} reportes)</span>
            </div>
          </div>
        )}

        {/* WHOIS */}
        {osintData?.whois && (
          <div className="flex flex-col space-y-2 justify-center">
            <span className="text-sm text-[#888]">Registrador WHOIS</span>
            <span className="text-base text-[#ededed] font-medium truncate" title={osintData.whois.registrar || 'Privado'}>
              {osintData.whois.registrar || 'Privado'}
            </span>
          </div>
        )}

        {/* SSL */}
        {osintData?.ssl && (
          <div className="flex flex-col space-y-2 justify-center">
            <span className="text-sm text-[#888]">Certificado SSL</span>
            <span className="text-base text-[#ededed] font-medium truncate" title={osintData.ssl.issuer || 'Desconocido'}>
              {osintData.ssl.issuer || 'Desconocido'}
            </span>
          </div>
        )}

      </div>
    </div>
  );
}
