import { useState, useRef } from 'react';
import axios from 'axios';
import { ChatMessage } from '@/features/analyzer/components/ResultsComponents/tabs/SummaryTab';
import { ScanResult } from '@/types';
import { API_URL } from '@/lib/api';

export function useAiChat(scanResult: ScanResult) {
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [isChatLoading, setIsChatLoading] = useState(false);
  // Bug #7 fix: ref guard para evitar doble envío en rápida sucesión (race condition)
  const isSubmittingRef = useRef(false);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || isChatLoading || isSubmittingRef.current) return;

    isSubmittingRef.current = true;

    const newMessage: ChatMessage = { role: 'user', content: chatInput.trim() };
    const updatedMessages = [...chatMessages, newMessage];

    setChatMessages(updatedMessages);
    setChatInput('');
    setIsChatLoading(true);

    // Fix Caos #3: el backend tiene max_length=20 en messages.
    // Recortamos al 18 más recientes para no romper el chat silenciosamente.
    const MAX_MESSAGES_TO_SEND = 18;
    const messagesToSend = updatedMessages.slice(-MAX_MESSAGES_TO_SEND);

    try {
      const response = await axios.post(`${API_URL}/api/chat`, {
        messages: messagesToSend,
        scan_context: scanResult
      });

      if (response.data.reply) {
        setChatMessages(prev => [...prev, { role: 'assistant', content: response.data.reply }]);
      } else {
        setChatMessages(prev => [...prev, { role: 'assistant', content: "Lo siento, ocurrió un error procesando tu solicitud." }]);
      }
    } catch {
      setChatMessages(prev => [...prev, { role: 'assistant', content: "Error de conexión con el servidor IA." }]);
    } finally {
      setIsChatLoading(false);
      isSubmittingRef.current = false;
    }
  };

  return {
    chatInput,
    setChatInput,
    chatMessages,
    isChatLoading,
    handleSendMessage
  };
}
