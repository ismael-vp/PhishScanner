import React from 'react';
import { Shield, ExternalLink } from 'lucide-react';

interface TechStackCardProps {
  technologies?: string[];
  externalScripts?: string[];
  onExplainScript?: (url: string) => void;
}

const TechStackCard: React.FC<TechStackCardProps> = ({ 
  // technologies no se está usando, se puede omitir o prefijar con un guion bajo
  technologies: _technologies = [], 
  externalScripts = [],
  onExplainScript 
}) => {
  return (
    <div className="space-y-8">
      {/* Sección Scripts Externos */}

      {externalScripts && externalScripts.length > 0 && (
        <div className="bg-black border border-[#333] rounded-lg p-6">
          <div className="flex items-center gap-3 mb-6">
            <Shield size={20} className="text-[#888]" />
            <h3 className="text-[#ededed] font-semibold text-lg">Scripts Externos Detectados</h3>
          </div>
          <div className="grid grid-cols-1 gap-3">
            {externalScripts.map((script, index) => (
              <div 
                key={index} 
                className="flex items-center justify-between p-3 bg-[#0a0a0a] border border-[#222] rounded-md group hover:border-[#333] transition-colors"
              >
                <span className="text-xs font-mono text-[#888] truncate max-w-[80%]" title={script}>
                  {script}
                </span>
                {onExplainScript && (
                  <button
                    onClick={() => onExplainScript(script)}
                    className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-[#555] hover:text-[#ededed] transition-colors"
                  >
                    Analizar <ExternalLink size={10} />
                  </button>
                )}
              </div>
            ))}
          </div>
          <p className="mt-4 text-[11px] text-[#555] leading-relaxed italic">
            * Estos scripts se cargan desde dominios de terceros. Algunos pueden ser analíticas o CDNs, pero otros podrían ser trackers o inyecciones maliciosas.
          </p>
        </div>
      )}
    </div>
  );
};

export default TechStackCard;
