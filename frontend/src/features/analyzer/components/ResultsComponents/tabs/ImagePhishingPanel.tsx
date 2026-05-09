"use client";

import React from 'react';
import { ImagePhishingResult } from '@/types';
import { ShieldAlert, ShieldCheck, AlertTriangle, FileText, ExternalLink, ScanLine } from 'lucide-react';
import { useThreatStore } from '@/store/useThreatStore';
import { useAiChat } from '@/hooks/useAiChat';
import AiChatPanel from '../ui/AiChatPanel';
import { ScanResult } from '@/types';
import { API_URL } from '@/lib/api';

interface ImagePhishingPanelProps {
  analysis: ImagePhishingResult;
  imageName: string;
}

const CONFIDENCE_COLORS: Record<string, string> = {
  Alta: 'text-red-400 bg-red-500/10 border-red-500/20',
  Media: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  Baja: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
};

export default function ImagePhishingPanel({ analysis, imageName }: ImagePhishingPanelProps) {
  const { setMode, setError, setScanResult, setIsScanning, scanResult } = useThreatStore();
  const { is_phishing, confidence, verdict, red_flags, extracted_text, extracted_urls } = analysis;

  // Reutilizamos el mismo hook de chat que usa el tab de URL/archivo
  const aiChat = useAiChat(scanResult as ScanResult);

  const handleScanUrl = async (url: string) => {
    setMode('url');
    setError(null);
    setIsScanning(true);
    setScanResult(null);
    try {
      const axios = (await import('axios')).default;
      const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await axios.post(`${API_URL}/api/analyze/url`, { url: normalizedUrl });
      setScanResult(response.data, normalizedUrl);
    } catch {
      setError('No se pudo analizar la URL extraída de la imagen.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto mt-8 animate-in fade-in slide-in-from-bottom-4 duration-700 space-y-6">

      {/* Veredicto Principal */}
      <div className={`rounded-lg border p-6 flex items-start space-x-5 ${
        is_phishing
          ? 'bg-red-500/5 border-red-900/50'
          : 'bg-green-500/5 border-green-900/40'
      }`}>
        <div className={`p-2.5 rounded-xl border flex-shrink-0 ${
          is_phishing ? 'bg-red-500/10 border-red-500/20' : 'bg-green-500/10 border-green-500/20'
        }`}>
          {is_phishing
            ? <ShieldAlert size={36} className="text-red-500" />
            : <ShieldCheck size={36} className="text-green-500" />
          }
        </div>
        <div className="flex-1">
          <div className="flex items-center space-x-3 mb-2">
            <h2 className="text-2xl font-bold text-white tracking-tight">
              {is_phishing ? 'Señales de Phishing' : 'Sin señales de peligro'}
            </h2>
            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase tracking-widest ${
              is_phishing ? 'text-red-500 border-red-500/20 bg-red-500/10' : 'text-green-500 border-green-500/20 bg-green-500/10'
            }`}>
              {is_phishing ? 'Inseguro' : 'Seguro'}
            </span>
            {confidence !== 'Baja' && (
              <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase tracking-widest ${
                CONFIDENCE_COLORS[confidence] ?? 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20'
              }`}>
                Confianza {confidence}
              </span>
            )}

          </div>
          <p className="text-sm text-zinc-400 leading-relaxed">{imageName}</p>
          <p className="text-base text-zinc-300 leading-relaxed mt-3">{verdict}</p>
        </div>
      </div>

      {/* Señales de Alerta */}
      {red_flags && red_flags.length > 0 && (
        <div className="bg-black border border-[#333] rounded-lg p-6">
          <h3 className="text-[#ededed] text-lg font-medium mb-4 flex items-center space-x-2">
            <AlertTriangle size={18} className="text-orange-500" />
            <span>Alertas detectadas ({red_flags.length})</span>
          </h3>
          <ul className="space-y-2.5">
            {red_flags.map((flag, idx) => (
              <li key={idx} className="flex items-start space-x-3">
                <span className="mt-1 w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0"></span>
                <span className="text-sm text-zinc-400 leading-relaxed">{flag}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* URLs Extraídas */}
      {extracted_urls && extracted_urls.length > 0 && (
        <div className="bg-black border border-[#333] rounded-lg p-6">
          <h3 className="text-[#ededed] text-lg font-medium mb-4 flex items-center space-x-2">
            <ExternalLink size={18} className="text-[#888]" />
            <span>URLs Encontradas en la Imagen</span>
          </h3>
          <div className="space-y-2">
            {extracted_urls.map((url, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-[#050505] border border-[#222] rounded-md group">
                <span className="text-sm font-mono text-zinc-400 truncate flex-1 mr-4">{url}</span>
                <button
                  onClick={() => handleScanUrl(url)}
                  className="flex items-center space-x-1.5 text-xs font-medium text-white bg-[#111] border border-[#333] px-3 py-1.5 rounded-md hover:bg-[#222] transition-colors flex-shrink-0"
                >
                  <ScanLine size={12} />
                  <span>Escanear URL</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Texto OCR extraído (colapsable) */}
      {extracted_text && extracted_text.trim().length > 0 && (
        <details className="bg-black border border-[#333] rounded-lg">
          <summary className="p-6 cursor-pointer text-[#ededed] text-base font-medium flex items-center space-x-2 select-none hover:text-white transition-colors">
            <FileText size={16} className="text-[#888]" />
            <span>Texto Extraído por OCR</span>
          </summary>
          <div className="px-6 pb-6">
            <pre className="text-sm text-zinc-500 whitespace-pre-wrap font-mono leading-relaxed bg-[#050505] border border-[#222] rounded-md p-4 max-h-64 overflow-y-auto custom-scrollbar">
              {extracted_text}
            </pre>
          </div>
        </details>
      )}

      {/* Sin señales */}
      {!is_phishing && (!red_flags || red_flags.length === 0) && (
        <div className="bg-black border border-[#333] rounded-lg p-6 text-center">
          <ShieldCheck size={32} className="text-green-500/50 mx-auto mb-3" />
          <p className="text-sm text-zinc-500">
            No hemos encontrado elementos engañosos en esta imagen.
          </p>
        </div>
      )}

      {/* Chat de IA */}
      <AiChatPanel 
        chatMessages={aiChat.chatMessages}
        chatInput={aiChat.chatInput}
        setChatInput={aiChat.setChatInput}
        isChatLoading={aiChat.isChatLoading}
        handleSendMessage={aiChat.handleSendMessage}
        placeholder="Ej. ¿Por qué se considera phishing esta imagen?"
        emptyStateMessage="Puedes preguntarme sobre los resultados del análisis de la imagen, las URLs detectadas o las señales de alerta encontradas."
      />

    </div>
  );
}


