import React from 'react';
import { CheckCircle2, Loader2, Circle } from 'lucide-react';

interface ScannerLoaderProps {
  currentStep: number;
  mode?: 'url' | 'image';
}

const URL_STEPS = [
  'Resolviendo DNS y conectando con el servidor',
  'Analizando estructura y riesgos de typosquatting',
  'Consultando motores de inteligencia y reputación',
  'Sintetizando veredicto final',
];

const IMAGE_STEPS = [
  'Extrayendo metadatos y biometría de la imagen',
  'Ejecutando motor OCR para extracción de texto',
  'Analizando contenido semántico con IA forense',
  'Generando reporte de riesgos visuales',
];

export default function ScannerLoader({ currentStep, mode = 'url' }: ScannerLoaderProps) {
  const steps = mode === 'url' ? URL_STEPS : IMAGE_STEPS;
  const progress = (currentStep / steps.length) * 100;


  return (
    <div className="w-full max-w-xl mx-auto mt-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="bg-zinc-950 border border-zinc-800/50 rounded-lg overflow-hidden relative shadow-2xl">
        
        {/* Barra de progreso superior */}
        <div className="absolute top-0 left-0 w-full h-[1px] bg-zinc-900">
          <div 
            className="h-full bg-zinc-200 transition-all duration-700 ease-out"
            style={{ width: `${progress}%` }}
          ></div>
        </div>

        <div className="p-8">
          <div className="flex items-center justify-between mb-8">
            <h3 className="text-zinc-100 text-sm font-medium tracking-tight">Proceso de Análisis</h3>
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">
              Paso {currentStep} de {steps.length}
            </span>
          </div>

          <div className="space-y-5">
            {steps.map((label, index) => {

              const stepNumber = index + 1;
              const isCompleted = stepNumber < currentStep;
              const isCurrent = stepNumber === currentStep;
              const isPending = stepNumber > currentStep;

              return (
                <div 
                  key={index} 
                  className="flex items-start space-x-4 group transition-all duration-300"
                >
                  <div className="flex-shrink-0 mt-0.5">
                    {isCompleted && (
                      <CheckCircle2 size={16} className="text-zinc-500" />
                    )}
                    {isCurrent && (
                      <Loader2 size={16} className="text-zinc-200 animate-spin" />
                    )}
                    {isPending && (
                      <Circle size={16} className="text-zinc-800" />
                    )}
                  </div>
                  
                  <p className={`text-sm font-medium transition-colors duration-300 ${
                    isCompleted ? 'text-zinc-500 line-through decoration-zinc-800' : 
                    isCurrent ? 'text-zinc-200 animate-pulse' : 
                    'text-zinc-700'
                  }`}>
                    {label}
                  </p>
                </div>
              );
            })}
          </div>

          <div className="mt-10 pt-6 border-t border-zinc-900 flex justify-between items-center">
            <div className="flex items-center space-x-2">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></div>
              <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-tighter">
                Sistema de Detección Heurística v2.1
              </span>
            </div>
            <span className="text-[10px] text-zinc-700 font-mono">
              SECURE_ORCHESTRATOR_ID: TX-44
            </span>
          </div>
        </div>
      </div>
      
      <p className="text-center text-[10px] text-zinc-600 mt-6 uppercase tracking-[0.2em] font-medium">
        Analizando Amenazas en Tiempo Real
      </p>
    </div>
  );
}
