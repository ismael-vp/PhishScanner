import React from 'react';
import { Layers } from 'lucide-react';
import { ScanResult } from '@/types';

interface UrlAnatomyCardProps {
  anatomy: NonNullable<NonNullable<ScanResult['osint_data']>['url_anatomy']>;
  isTyposquatting?: boolean;
}

export default function UrlAnatomyCard({ anatomy, isTyposquatting }: UrlAnatomyCardProps) {
  const isCritical = !!anatomy.hosting_brand_alert || !!isTyposquatting;
  
  const flags = [
    anatomy.is_ip,
    anatomy.suspicious_tld,
    anatomy.excessive_subdomains,
    anatomy.excessive_hyphens,
    (anatomy.phishing_keywords?.length ?? 0) > 0,
    anatomy.length_warning,
    isCritical
  ].filter(Boolean).length;

  const warnings = [];
  
  if (anatomy.hosting_brand_alert) {
    warnings.push({
      title: 'Uso de Marca en Hosting de Terceros',
      desc: (
        <>
          Se ha detectado el nombre de una marca oficial (<span className="font-bold text-zinc-300">{anatomy.hosting_brand_alert.brand}</span>) 
          dentro de un subdominio de <span className="font-bold text-zinc-300">{anatomy.hosting_brand_alert.provider}</span>. 
          Las marcas legítimas nunca usan estos servicios para sus páginas oficiales.
        </>
      ),
      critical: true
    });
  }

  if (isTyposquatting) {
    warnings.push({
      title: 'Suplantación de Marca (Typosquatting)',
      desc: 'El dominio parece una variación visual de una marca conocida, diseñada para engañar al usuario.',
      critical: true
    });
  }

  if (anatomy.is_ip) warnings.push({
    title: 'Dirección Numérica (IP)',
    desc: 'Utiliza una IP en lugar de un nombre de dominio para ocultar la identidad del servidor.'
  });
  if (anatomy.suspicious_tld) warnings.push({
    title: 'Extensión Inusual',
    desc: 'Utiliza un TLD frecuentemente asociado con campañas de spam o sitios efímeros.'
  });
  if (anatomy.excessive_subdomains) warnings.push({
    title: 'Exceso de Subniveles',
    desc: 'Tiene demasiados subdominios, una técnica para simular rutas legítimas.'
  });
  if (anatomy.excessive_hyphens) warnings.push({
    title: 'Guiones Repetitivos',
    desc: 'El dominio contiene múltiples guiones para parecerse a marcas oficiales.'
  });
  if ((anatomy.phishing_keywords?.length ?? 0) > 0) warnings.push({
    title: 'Palabras Clave de Engaño',
    desc: `Contiene términos como [${anatomy.phishing_keywords?.join(', ')}] de engaño.`
  });
  if (anatomy.length_warning) warnings.push({
    title: 'URL Extremadamente Larga',
    desc: 'La longitud supera los 75 caracteres, ocultando el final real del enlace.'
  });

  return (
    <div>
      <h4 className="text-[#ededed] text-xl font-medium mb-4 flex items-center space-x-2">
        <Layers size={20} className="text-[#888]" />
        <span>Anatomía del Enlace</span>
      </h4>
      
      <div className="bg-black border border-zinc-800 rounded-md p-6 relative overflow-hidden group">
        <div className="absolute top-0 right-0 p-6 flex flex-col items-end">
          <span className="text-[10px] uppercase tracking-widest text-[#555] font-bold mb-1">Estructura</span>
          <div className="flex items-center space-x-2">
            {isCritical ? (
              <span className="text-xs font-mono text-red-500 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 uppercase">Anomalía</span>
            ) : flags === 0 ? (
              <span className="text-xs font-mono text-green-500/80 bg-green-500/5 px-2 py-0.5 rounded border border-green-500/20 uppercase">Estándar</span>
            ) : (
              <span className="text-xs font-mono text-orange-500/80 bg-orange-500/5 px-2 py-0.5 rounded border border-orange-500/20 uppercase">Atípica</span>
            )}
          </div>
        </div>

        <div className="space-y-6">
          {warnings.length === 0 ? (
            <div className="flex items-center space-x-3 py-2 text-zinc-500">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500/50"></div>
              <p className="text-sm">Estructura de URL legítima.</p>
            </div>
          ) : (
            warnings.map((w, i) => (
              <div key={i} className="flex items-start gap-3 py-1">
                <div className={`w-1.5 h-1.5 rounded-full ${w.critical ? 'bg-red-500 animate-pulse shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 'bg-zinc-700'} flex-shrink-0 mt-1.5`}></div>
                <div>
                  <h5 className="text-sm font-medium text-zinc-100 mb-1">{w.title}</h5>
                  <div className="text-[13px] text-zinc-500 leading-relaxed max-w-xl">{w.desc}</div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
