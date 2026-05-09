import { useState } from 'react';
import axios from 'axios';
import { ChatMessage } from '@/features/analyzer/components/ResultsComponents/tabs/SummaryTab';
import { ScanResult } from '@/types';
import { API_URL } from '@/lib/api';

export function useAiChat(scanResult: ScanResult) {
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [isChatLoading, setIsChatLoading] = useState(false);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || isChatLoading) return;

    const newMessage: ChatMessage = { role: 'user', content: chatInput.trim() };
    const updatedMessages = [...chatMessages, newMessage];

    setChatMessages(updatedMessages);
    setChatInput('');
    setIsChatLoading(true);

    try {
      const response = await axios.post(`${API_URL}/api/chat`, {
        messages: updatedMessages,
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
