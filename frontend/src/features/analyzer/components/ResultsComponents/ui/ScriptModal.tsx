import React from 'react';
import { Sparkles } from 'lucide-react';

interface ScriptModalProps {
  selectedScript: string | null;
  scriptExplanation: string | null;
  isExplainingScript: boolean;
  onClose: () => void;
}

export default function ScriptModal({
  selectedScript,
  scriptExplanation,
  isExplainingScript,
  onClose
}: ScriptModalProps) {
  if (!selectedScript) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <div className="bg-black border border-[#333] p-6 max-w-md w-full rounded-lg shadow-2xl flex flex-col">
        <h3 className="text-[#ededed] font-medium text-lg mb-2 flex items-center space-x-2">
          <Sparkles size={18} className="text-[#888]" />
          <span>Análisis del Script</span>
        </h3>
        <p className="text-[#888] font-mono text-xs truncate mb-6 pb-4 border-b border-[#333]" title={selectedScript}>
          {selectedScript}
        </p>

        <div className="min-h-[100px] mb-6">
          {isExplainingScript ? (
            <div className="flex flex-col space-y-3 animate-pulse">
              <div className="h-4 bg-[#222] rounded w-3/4"></div>
              <div className="h-4 bg-[#222] rounded w-full"></div>
              <div className="h-4 bg-[#222] rounded w-5/6"></div>
            </div>
          ) : (
            <p className="text-[#ededed] text-sm leading-relaxed whitespace-pre-wrap">
              {scriptExplanation}
            </p>
          )}
        </div>

        <button
          onClick={onClose}
          className="mt-auto py-2.5 bg-[#ededed] hover:bg-white text-black text-sm font-medium rounded-md transition-colors w-full"
        >
          Cerrar
        </button>
      </div>
    </div>
  );
}
