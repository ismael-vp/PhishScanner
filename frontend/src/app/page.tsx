import React from 'react';
import AnalyzeForm from '@/features/analyzer/components/AnalyzeForm';
import ResultsPanel from '@/features/analyzer/components/ResultsPanel';
import HistoryPanel from '@/features/history/components/HistoryPanel';
import { ShieldAlert } from 'lucide-react';

export default function Home() {
  return (
    <div className="min-h-screen bg-black text-[#ededed] font-sans selection:bg-[#333] selection:text-white pb-20">
      
      {/* Navbar Súper Minimalista */}
      <header className="border-b border-[#333] bg-black/80 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <h1 className="text-sm font-medium tracking-wide text-white" translate="no">
              PhishScanner
            </h1>
          </div>
        </div>
      </header>

      {/* Bloqueo para Móviles */}
      <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black px-8 text-center md:hidden">
        <div className="w-16 h-[1px] bg-zinc-800 mb-8"></div>
        <h2 className="text-xl font-bold text-white mb-4 tracking-tight">Acceso Restringido</h2>
        <p className="text-sm text-zinc-500 leading-relaxed max-w-xs">
          PhishScanner está optimizado para su uso en estaciones de trabajo y pantallas de gran formato. 
          <br /><br />
          Por favor, accede desde un ordenador para realizar análisis de seguridad.
        </p>
        <div className="w-16 h-[1px] bg-zinc-800 mt-8"></div>
      </div>

      {/* Contenido Principal (Oculto en móvil) */}
      <main className="hidden md:flex w-full max-w-5xl mx-auto px-4 py-16 flex-col items-center">
        
        {/* Zona de Trabajo */}
        <div className="w-full space-y-6">
          <AnalyzeForm />
          <ResultsPanel />
          <HistoryPanel />
        </div>

      </main>

    </div>
  );
}
