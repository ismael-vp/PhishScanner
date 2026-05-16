import React from 'react';

import { ScanResult } from '@/types';
import UrlAnatomyCard from '@/features/analyzer/components/ResultsComponents/cards/UrlAnatomyCard';
import HeuristicRiskCard from '@/features/analyzer/components/ResultsComponents/cards/HeuristicRiskCard';
import HeuristicReportCard from '@/features/analyzer/components/ResultsComponents/cards/HeuristicReportCard';
import PrivacyNutritionLabel from '@/features/analyzer/components/ResultsComponents/cards/PrivacyNutritionLabel';

import SecurityVerdict from '@/features/analyzer/components/ResultsComponents/ui/SecurityVerdict';
import SeverityBanner from '@/features/analyzer/components/ResultsComponents/ui/SeverityBanner';
import AiChatPanel from '@/features/analyzer/components/ResultsComponents/ui/AiChatPanel';
import SecureCaptureCard from '@/features/analyzer/components/ResultsComponents/cards/SecureCaptureCard';

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface SummaryTabProps {
  scanResult: ScanResult;
  chatMessages: ChatMessage[];
  chatInput: string;
  setChatInput: (val: string) => void;
  isChatLoading: boolean;
  handleSendMessage: (e: React.FormEvent) => void;
}

export default function SummaryTab({
  scanResult,
  chatMessages,
  chatInput,
  setChatInput,
  isChatLoading,
  handleSendMessage
}: SummaryTabProps) {
  const { ai_summary, osint_data, type } = scanResult;

  // Formateo de URL Obligatorio y seguro (preferimos https por defecto)
  const safeUrl = scanResult.resourceName 
    ? (scanResult.resourceName.startsWith('http') ? scanResult.resourceName : `https://${scanResult.resourceName}`)
    : '';

  return (
    <div className="space-y-10 animate-in fade-in duration-500">
      {/* Cabecera del Veredicto */}
      <div className="flex flex-col gap-4">
        <SecurityVerdict scanResult={scanResult} />

        {scanResult.stats && (
          <SeverityBanner 
            isMalicious={(scanResult.stats?.malicious || 0) > 0 || (scanResult.stats?.suspicious || 0) > 0} 
            maliciousCount={(scanResult.stats?.malicious || 0) + (scanResult.stats?.suspicious || 0)} 
            totalEngines={(scanResult.stats?.malicious || 0) + (scanResult.stats?.suspicious || 0) + (scanResult.stats?.undetected || 0) + (scanResult.stats?.harmless || 0)} 
          />
        )}
      </div>

      {/* Bloque de Evidencias Técnicas */}
      <div className="flex flex-col gap-6">
        {/* Componente Unificado de Alertas de Riesgo */}
        <HeuristicRiskCard 
          hasDangerousForm={osint_data?.has_dangerous_form}
          isTyposquatting={osint_data?.is_typosquatting}
          targetBrand={osint_data?.target_brand}
          hostname={scanResult.resourceName}
        />

        {/* Nueva etiqueta de nutrición de privacidad (Apple Style) */}
        {osint_data?.privacy_analysis && (
          <PrivacyNutritionLabel privacy={osint_data.privacy_analysis} />
        )}

        {/* Análisis Heurístico Avanzado (Nueva Versión Facade) */}
        {type === 'url' && osint_data?.heuristic_result && (
          <HeuristicReportCard result={osint_data.heuristic_result} />
        )}

        {/* Fallback para Análisis de Anatomía (Legacy) */}
        {type === 'url' && !osint_data?.heuristic_result && osint_data?.url_anatomy && (
          <UrlAnatomyCard 
            anatomy={osint_data.url_anatomy} 
            isTyposquatting={osint_data.is_typosquatting}
          />
        )}


        {/* Cadena de Redirecciones (Solo URLs con redirecciones) */}
        {type === 'url' && osint_data?.redirect_chain && (osint_data?.redirect_chain?.length ?? 0) > 1 && (
          <div className="animate-in fade-in duration-500">
            <h4 className="text-[#ededed] text-xl font-semibold mb-4 flex items-center space-x-2">
              <span>Cadena de Redirecciones</span>
            </h4>
            <div className="bg-[#050505] border border-[#333] rounded-md p-6">
              <div className="flex flex-col space-y-6 relative">
                <div className="absolute top-3 bottom-3 left-[9px] w-[1px] border-l border-[#333] z-0"></div>
                {osint_data?.redirect_chain?.map((link: string, idx: number, arr: string[]) => {
                  const isLast = idx === arr.length - 1;
                  return (
                    <div key={idx} className="flex items-start space-x-4 relative z-10">
                      <div className={`mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center ${isLast ? 'bg-[#ededed] text-black' : 'bg-[#050505] border border-[#555]'}`}>
                        {isLast ? <div className="w-2 h-2 rounded-full bg-black"></div> : <div className="w-1.5 h-1.5 rounded-full bg-[#555]"></div>}
                      </div>
                      <span className={`text-sm font-mono truncate ${isLast ? 'text-[#ededed] font-medium' : 'text-[#888]'}`} title={link}>
                        {link}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Captura Multi-Dispositivo (Cloaking) */}
        {type === 'url' && (
          <SecureCaptureCard osintData={osint_data} safeUrl={safeUrl} />
        )}
      </div>


      {/* Resumen IA */}
      <h4 className="text-[#ededed] text-xl font-medium flex items-center space-x-2 pt-4">
        <span>Análisis por Inteligencia Artificial</span>
      </h4>
      <div className="border-l-2 border-zinc-700 pl-4 py-1">
        <p className="text-sm text-zinc-400 leading-relaxed whitespace-pre-wrap">
          {/* CORRECCIÓN DE NULOS AQUÍ */}
          {ai_summary 
            ? (typeof ai_summary === 'string' ? ai_summary : (ai_summary?.summary || "Resumen no disponible.")) 
            : "Resumen no disponible."}
        </p>
      </div>

      {/* Acciones Recomendadas */}
      {ai_summary && typeof ai_summary !== 'string' && ai_summary?.action_steps && Array.isArray(ai_summary.action_steps) && ai_summary.action_steps.length > 0 && (
        <div className="border-t border-[#333] mt-6 pt-6 animate-in fade-in duration-500">
          <h5 className="text-sm font-medium text-[#ededed] mb-4">Acciones Recomendadas</h5>
          <ul className="space-y-3">
            {ai_summary.action_steps.map((step: string, idx: number) => (
              <li key={idx} className="flex items-start space-x-3">
                <span className="text-zinc-600 mt-0.5 shrink-0 text-sm font-bold">•</span>
                <span className="text-sm text-zinc-400">{step}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Chat Contextual Integrado */}
      <AiChatPanel
        chatMessages={chatMessages}
        chatInput={chatInput}
        setChatInput={setChatInput}
        isChatLoading={isChatLoading}
        handleSendMessage={handleSendMessage}
        placeholder="Ej. ¿Qué significa que haya devuelto timeout?"
        emptyStateMessage="Puedes pedirle aclaraciones técnicas sobre el reporte."
      />

    </div>
  );
}