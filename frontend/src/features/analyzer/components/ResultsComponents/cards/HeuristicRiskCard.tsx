import React from 'react';
import { Layers } from 'lucide-react';

interface HeuristicRiskCardProps {
  hasDangerousForm?: boolean;
  isTyposquatting?: boolean;
  targetBrand?: string | null;
  hostname?: string | null;
}

export default function HeuristicRiskCard({
  hasDangerousForm,
  isTyposquatting,
  targetBrand,
  hostname,
}: HeuristicRiskCardProps) {
  if (!hasDangerousForm && !isTyposquatting) {
    return null;
  }

  return (
    <div className="">
      <h4 className="text-[#ededed] text-xl font-semibold mb-4 flex items-center space-x-2">
        <span>Posible Phishing</span>
      </h4>

      <div className="bg-[#050505] border border-[#333] rounded-md p-6 space-y-6">

        {/* Hallazgo 1: Intento de Robo de Datos */}
        {hasDangerousForm && (
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 group/item py-1">
            <div className="flex items-start gap-3 flex-1">
              <div className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0 mt-1.5"></div>
              <div>
                <h5 className="text-sm font-medium text-[#ededed] mb-1">Formulario Sospechoso</h5>
                <p className="text-xs text-[#888] leading-relaxed max-w-xl">
                  Hemos encontrado un formulario que podría intentar engañarte para obtener tus contraseñas o datos.
                </p>
              </div>
            </div>
            <div className="shrink-0 flex items-start">
              <span className="text-[10px] font-mono uppercase tracking-widest text-red-500/80 bg-red-500/5 px-2 py-0.5 rounded border border-red-500/20">
                RIESGO ALTO
              </span>
            </div>
          </div>
        )}

        {/* Separador si hay múltiples hallazgos */}
        {hasDangerousForm && isTyposquatting && (
          <div className="border-t border-[#333] w-full"></div>
        )}

        {/* Hallazgo 2: Typosquatting */}
        {isTyposquatting && (
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 group/item py-1">
            <div className="flex items-start gap-3 flex-1">
              <div className="w-2 h-2 rounded-full bg-orange-500 flex-shrink-0 mt-1.5"></div>
              <div>
                <h5 className="text-sm font-medium text-[#ededed] mb-1">Dominio Engañoso</h5>
                <p className="text-xs text-[#888] leading-relaxed max-w-xl">
                  Este enlace se parece mucho a una marca conocida, lo que suele ser un intento de engaño ({hostname} vs {targetBrand?.toLowerCase()}.com).
                </p>
              </div>
            </div>
            <div className="shrink-0 flex items-start">
              <span className="text-[10px] font-mono uppercase tracking-widest text-orange-500/80 bg-orange-500/5 px-2 py-0.5 rounded border border-orange-500/20">
                RIESGO MEDIO
              </span>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
