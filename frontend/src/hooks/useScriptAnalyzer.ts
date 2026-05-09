import { useState } from 'react';
import axios from 'axios';
import { API_URL } from '@/lib/api';

export function useScriptAnalyzer() {
  const [selectedScript, setSelectedScript] = useState<string | null>(null);
  const [scriptExplanation, setScriptExplanation] = useState<string | null>(null);
  const [isExplainingScript, setIsExplainingScript] = useState(false);

  const handleExplainScript = async (scriptUrl: string) => {
    setSelectedScript(scriptUrl);
    setScriptExplanation(null);
    setIsExplainingScript(true);
    try {
      const response = await axios.post(`${API_URL}/api/explain-script`, {
        script_url: scriptUrl
      });
      setScriptExplanation(response.data.explanation);
    } catch {
      setScriptExplanation("Hubo un error al generar la explicación con IA.");
    } finally {
      setIsExplainingScript(false);
    }
  };

  const closeScriptModal = () => setSelectedScript(null);

  return {
    selectedScript,
    scriptExplanation,
    isExplainingScript,
    handleExplainScript,
    closeScriptModal
  };
}
