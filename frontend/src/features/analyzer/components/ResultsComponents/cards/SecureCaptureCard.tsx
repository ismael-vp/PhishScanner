"use client";

import React, { useState } from 'react';
import { Monitor, Smartphone, ExternalLink } from 'lucide-react';
import { OSINTData } from '@/types';

interface SecureCaptureCardProps {
  osintData?: OSINTData | null;
  safeUrl: string;
}

export default function SecureCaptureCard({ osintData, safeUrl }: SecureCaptureCardProps) {
  const [activeView, setActiveView] = useState<'desktop' | 'mobile'>('desktop');
  const [isLoading, setIsLoading] = useState(true);
  const [hasError, setHasError] = useState(false);
  const [forceMobileView, setForceMobileView] = useState(false);

  const desktopUrl = osintData?.screenshot_desktop;
  const mobileUrl = osintData?.screenshot_mobile;
  const isMobileOptimized = osintData?.is_mobile_optimized ?? true;
  
  const currentImageUrl = activeView === 'desktop' ? desktopUrl : mobileUrl;

  // Timeout de seguridad
  React.useEffect(() => {
    if (currentImageUrl) {
      const timer = setTimeout(() => {
        setIsLoading(false);
      }, 20000);
      return () => clearTimeout(timer);
    }
  }, [currentImageUrl]);

  if (!desktopUrl && !mobileUrl) return null;

  return (
    <div className="animate-in fade-in duration-500">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-[#ededed] text-xl font-semibold flex items-center space-x-2">
          <span>Captura del Sitio</span>
        </h4>
        
        {/* Toggle Desktop / Mobile */}
        <div className="flex items-center p-1 bg-zinc-900 border border-zinc-800 rounded-md">
          <button
            onClick={() => {
              if (activeView !== 'desktop') {
                setActiveView('desktop');
                if (desktopUrl) {
                  setIsLoading(true);
                  setHasError(false);
                }
              }
            }}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
              activeView === 'desktop'
                ? 'bg-zinc-800 text-zinc-100 shadow-sm'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            <Monitor size={14} />
            <span>Desktop</span>
          </button>
          <button
            onClick={() => {
              if (activeView !== 'mobile') {
                setActiveView('mobile');
                if (mobileUrl) {
                  setIsLoading(true);
                  setHasError(false);
                }
              }
            }}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
              activeView === 'mobile'
                ? 'bg-zinc-800 text-zinc-100 shadow-sm'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            <Smartphone size={14} />
            <span>Mobile</span>
          </button>
        </div>
      </div>

      <div className={`relative bg-[#050505] border border-[#333] rounded-md overflow-hidden group flex items-center justify-center ${activeView === 'desktop' ? 'aspect-video' : 'py-12'}`}>
        
        {/* Enlace Externo */}
        <div className="absolute top-4 right-4 z-20 flex space-x-2">
          <a 
            href={safeUrl} 
            target="_blank" 
            rel="noopener noreferrer"
            className="px-4 py-1.5 text-sm font-medium text-zinc-300 bg-[#1e1e1e] border border-zinc-700 rounded-md hover:bg-zinc-700 hover:text-white transition-all shadow-sm flex items-center gap-2 backdrop-blur-sm"
          >
            <ExternalLink size={14} />
            Ver original
          </a>
          <span className="text-[10px] text-green-500/80 bg-green-500/5 px-2 py-1 rounded border border-green-500/20 font-mono uppercase tracking-widest backdrop-blur-sm flex items-center">
            Aislamiento Activo
          </span>
        </div>

        {/* Cargando */}
        {isLoading && !hasError && (activeView === 'desktop' || (isMobileOptimized || forceMobileView)) && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#050505] z-10">
            <span className="text-sm text-zinc-500 font-medium animate-pulse">Cargando vistas...</span>
          </div>
        )}

        {/* Error */}
        {(hasError || !currentImageUrl) ? (
          <div className="flex flex-col items-center justify-center p-8 text-center space-y-3 bg-[#0a0a0a] w-full h-full border border-dashed border-[#222]">
            <Monitor size={32} className="text-[#333]" />
            <p className="text-sm text-[#555] max-w-[280px]">
              Vista previa no disponible.
            </p>
          </div>
        ) : (
          <div className={`w-full transition-opacity duration-700 ${isLoading && (activeView === 'desktop' || (isMobileOptimized || forceMobileView)) ? 'opacity-0' : 'opacity-100'}`}>
            {activeView === 'desktop' ? (
              /* eslint-disable-next-line @next/next/no-img-element */
              <img 
                src={currentImageUrl}
                alt="Vista de Escritorio"
                onLoad={() => setIsLoading(false)}
                onError={() => { setIsLoading(false); setHasError(true); }}
                className="w-full h-full object-cover max-h-[600px] object-top"
              />
            ) : (
              <div className="border-[8px] border-zinc-950 rounded-3xl mx-auto w-fit overflow-hidden bg-black shadow-2xl relative">
                {/* Simulador de Isla dinámica o altavoz */}
                <div className="absolute top-0 inset-x-0 h-4 bg-zinc-950 rounded-b-xl mx-auto w-1/3 z-20"></div>
                
                {(!isMobileOptimized && !forceMobileView) ? (
                  <div className="w-[320px] h-[550px] bg-zinc-900/50 flex flex-col items-center justify-center text-center p-6">
                    <Smartphone size={32} className="text-zinc-500 opacity-50" />
                    <h5 className="text-sm font-medium text-zinc-300 mt-4">Sitio probablemente ilegible en móvil</h5>
                    <p className="text-xs text-zinc-500 mt-2 leading-relaxed">
                      La página parece tener un diseño no adaptativo, lo que resulta en textos amontonados y microscópicos en esta resolución.
                    </p>
                    <button 
                      onClick={() => setForceMobileView(true)}
                      className="text-[10px] text-zinc-400 underline mt-6 hover:text-zinc-300 transition-colors"
                    >
                      Forzar visualización
                    </button>
                  </div>
                ) : (
                  /* eslint-disable-next-line @next/next/no-img-element */
                  <img 
                    src={currentImageUrl}
                    alt="Vista Móvil"
                    onLoad={() => setIsLoading(false)}
                    onError={() => { setIsLoading(false); setHasError(true); }}
                    className="w-[320px] object-cover max-h-[650px] object-top bg-white"
                  />
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

