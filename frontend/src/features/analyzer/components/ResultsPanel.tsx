"use client";

import React, { useState } from 'react';
import { useThreatStore } from '@/store/useThreatStore';
import { AlertTriangle, RotateCcw } from 'lucide-react';
import SummaryTab from './ResultsComponents/tabs/SummaryTab';
import TechnicalTab from './ResultsComponents/tabs/TechnicalTab';
import { ScanResult } from '@/types';
import ScriptModal from './ResultsComponents/ui/ScriptModal';
import { useAiChat } from '@/hooks/useAiChat';
import { useScriptAnalyzer } from '@/hooks/useScriptAnalyzer';
import ImagePhishingPanel from './ResultsComponents/tabs/ImagePhishingPanel';

import { ErrorBoundary } from '@/components/ui/ErrorBoundary';

function ResultsPanelInner() {
  const { scanResult, error, resetState } = useThreatStore();
  const [activeTab, setActiveTab] = useState<'ai' | 'technical'>('ai');

  // Asegurarnos de que no usamos los hooks si no hay scanResult, para que no dé error.
  // Sin embargo, React Hooks deben ser llamados en el mismo orden siempre.
  // Por lo que podemos llamar a los hooks y pasar un scanResult vacío o no llamarlos
  // Wait, if scanResult is null, the early return handles it. But we cannot early return BEFORE hooks.
  // We can provide a mock scanResult or just conditionally render a wrapper component?
  // Let's check how to handle this correctly.

  // Bug #3 fix: useAiChat siempre se llama (regla de hooks), pero nunca con null —
  // si scanResult es null pasamos un objeto vacío para que scan_context llegue como {}
  const aiChat = useAiChat((scanResult ?? {}) as ScanResult);
  const scriptAnalyzer = useScriptAnalyzer();

  if (error) {
    return (
      <div className="w-full max-w-2xl mx-auto mt-6 bg-black border border-red-900/50 p-4 rounded-lg flex items-start space-x-3">
        <AlertTriangle className="text-red-600 mt-0.5 flex-shrink-0" size={18} />
        <div className="text-sm text-red-500">
          {typeof error === 'string' ? error : JSON.stringify(error)}
        </div>
      </div>
    );
  }

  if (!scanResult) return null;

  // --- Image analysis: renders its own dedicated panel ---
  if (scanResult.type === 'image') {
    return (
      <div className="w-full">
        <div className="flex justify-end mb-2 w-full max-w-5xl mx-auto">
          <button
            onClick={() => { resetState(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
            className="flex items-center space-x-2 bg-[#050505] text-[#888] border border-[#333] hover:text-white hover:bg-[#111] transition-colors text-xs font-medium py-1.5 px-3 rounded-md"
          >
            <RotateCcw size={14} />
            <span>Nuevo Análisis</span>
          </button>
        </div>
        {scanResult.image_analysis ? (
          <ImagePhishingPanel
            analysis={scanResult.image_analysis}
            imageName={scanResult.resourceName || 'Imagen Analizada'}
          />
        ) : (
          <div className="text-sm text-[#888] text-center mt-8">No se pudo obtener el análisis de la imagen.</div>
        )}
      </div>
    );
  }

  const stats = scanResult.stats;
  const maliciousCount = (stats?.malicious || 0) + (stats?.suspicious || 0);
  const isMalicious = maliciousCount > 0;

  return (
    <div className="w-full max-w-5xl mx-auto mt-8 animate-in fade-in slide-in-from-bottom-4 duration-700 relative">

      <div className="flex justify-end mb-4">
        <button
          onClick={() => {
            resetState();
            window.scrollTo({ top: 0, behavior: 'smooth' });
          }}
          className="flex items-center space-x-2 bg-[#050505] text-[#888] border border-[#333] hover:text-white hover:bg-[#111] transition-colors text-xs font-medium py-1.5 px-3 rounded-md"
        >
          <RotateCcw size={14} />
          <span>Nuevo Análisis</span>
        </button>
      </div>


      <div className="bg-black border border-[#333] rounded-lg overflow-hidden shadow-sm">
        <div className="flex border-b border-zinc-900 bg-zinc-950/50 px-2 sm:px-6">
          <button
            onClick={() => setActiveTab('ai')}
            className={`py-4 px-4 sm:px-6 text-sm sm:text-base font-semibold flex items-center transition-all relative ${activeTab === 'ai' ? 'text-white' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            <span>Resumen</span>
            {activeTab === 'ai' && <span className="absolute bottom-[-1px] left-0 w-full h-[2px] bg-white rounded-t-full"></span>}
          </button>

          <button
            onClick={() => setActiveTab('technical')}
            className={`py-4 px-4 sm:px-6 text-sm sm:text-base font-semibold flex items-center transition-all relative ${activeTab === 'technical' ? 'text-white' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            <span>Datos Técnicos</span>
            {activeTab === 'technical' && <span className="absolute bottom-[-1px] left-0 w-full h-[2px] bg-white rounded-t-full"></span>}
          </button>
        </div>

        <div className="p-8">
          {activeTab === 'ai' ? (
            <SummaryTab
              key={scanResult.resourceName}
              scanResult={scanResult}
              chatMessages={aiChat.chatMessages}
              chatInput={aiChat.chatInput}
              setChatInput={aiChat.setChatInput}
              isChatLoading={aiChat.isChatLoading}
              handleSendMessage={aiChat.handleSendMessage}
            />
          ) : (
            <TechnicalTab
              scanResult={scanResult}
              isMalicious={isMalicious}
              onExplainScript={scriptAnalyzer.handleExplainScript}
            />
          )}
        </div>
      </div>

      <ScriptModal
        selectedScript={scriptAnalyzer.selectedScript}
        scriptExplanation={scriptAnalyzer.scriptExplanation}
        isExplainingScript={scriptAnalyzer.isExplainingScript}
        onClose={scriptAnalyzer.closeScriptModal}
      />

    </div>
  );
}

export default function ResultsPanel() {
  return (
    <div id="results-panel-wrapper">
      <ErrorBoundary>
        <ResultsPanelInner />
      </ErrorBoundary>
    </div>
  );
}
