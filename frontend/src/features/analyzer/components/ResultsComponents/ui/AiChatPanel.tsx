import React from 'react';
import { Send } from 'lucide-react';

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface AiChatPanelProps {
  chatMessages: ChatMessage[];
  chatInput: string;
  setChatInput: (val: string) => void;
  isChatLoading: boolean;
  handleSendMessage: (e: React.FormEvent) => void;
  placeholder?: string;
  emptyStateMessage?: string;
}

export default function AiChatPanel({
  chatMessages,
  chatInput,
  setChatInput,
  isChatLoading,
  handleSendMessage,
  placeholder = "Pregunta algo a la IA...",
  emptyStateMessage = "Puedes hacer preguntas sobre los resultados del análisis."
}: AiChatPanelProps) {
  return (
    <div className="bg-black border border-[#333] rounded-lg p-6">
      <h3 className="text-[#ededed] text-xl font-medium mb-6">Pregunta a la IA</h3>

      {/* Historial de Mensajes */}
      <div className="space-y-6 mb-6 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
        {chatMessages.map((msg, idx) => (
          <div key={idx} className="flex flex-col space-y-1.5">
            <span className="text-sm font-medium text-[#888]">
              {msg.role === 'user' ? 'Tú' : 'IA'}
            </span>
            <p className="text-base text-[#ededed] leading-relaxed whitespace-pre-wrap">
              {msg.content}
            </p>
          </div>
        ))}

        {isChatLoading && (
          <div className="flex flex-col space-y-1.5 animate-pulse">
            <span className="text-sm font-medium text-[#888]">IA</span>
            <p className="text-base text-[#555]">Analizando consulta...</p>
          </div>
        )}

        {chatMessages.length === 0 && !isChatLoading && (
          <p className="text-sm text-[#555] italic">{emptyStateMessage}</p>
        )}
      </div>

      {/* Input y Botón de Envío */}
      <form onSubmit={handleSendMessage} className="relative flex items-center">
        <input
          type="text"
          value={chatInput}
          onChange={(e) => setChatInput(e.target.value)}
          placeholder={placeholder}
          className="w-full bg-black border border-[#333] text-base text-[#ededed] rounded-md py-3 pl-4 pr-12 focus:outline-none focus:border-white transition-colors placeholder:text-[#555]"
          disabled={isChatLoading}
        />
        <button
          type="submit"
          disabled={!chatInput.trim() || isChatLoading}
          className="absolute right-3 p-2 text-[#ededed] disabled:text-[#444] hover:text-white transition-colors cursor-pointer disabled:cursor-not-allowed"
        >
          <Send size={18} />
        </button>
      </form>
    </div>
  );
}
