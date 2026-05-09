import React from 'react';
import { Eye, User, Camera, ShieldCheck } from 'lucide-react';
import { PrivacyData } from '@/types/osint';

interface PrivacyNutritionLabelProps {
  privacy: PrivacyData | null;
}

const PrivacyListSection = ({ 
  title, 
  icon: Icon, 
  items, 
  emptyMessage, 
  dangerDotColor = "bg-red-500/60",
  safeDotColor = "bg-green-500/50" 
}: { 
  title: string; 
  icon: React.ElementType; 
  items: string[]; 
  emptyMessage: string;
  dangerDotColor?: string;
  safeDotColor?: string;
}) => (
  <div className="space-y-4 lg:border-l lg:border-zinc-900 lg:pl-8 first:border-0 first:pl-0">
    <div className="flex items-center space-x-2">
      <Icon size={16} className="text-zinc-500" />
      <h5 className="text-sm font-semibold text-zinc-100">{title}</h5>
    </div>
    
    <div className="space-y-3">
      {items.length > 0 ? (
        items.map((item, idx) => (
          <div key={idx} className="flex items-start gap-3">
            <div className={`w-1.5 h-1.5 rounded-full ${dangerDotColor} mt-1.5 flex-shrink-0`}></div>
            <div>
              <p className="text-[13px] text-zinc-400 font-medium leading-relaxed">{item}</p>
            </div>
          </div>
        ))
      ) : (
        <div className="flex items-center space-x-2 py-1 text-zinc-400">
          <div className={`w-1.5 h-1.5 rounded-full ${safeDotColor} flex-shrink-0`}></div>
          <p className="text-[13px]">{emptyMessage}</p>
        </div>
      )}
    </div>
  </div>
);

export default function PrivacyNutritionLabel({ privacy }: PrivacyNutritionLabelProps) {
  if (!privacy) return null;

  const { tracking_used, trackers_count, data_linked, device_access } = privacy;

  return (
    <div className="animate-in fade-in duration-700">
      {/* Encabezado consistente */}
      <h4 className="text-[#ededed] text-xl font-medium mb-4 flex items-center space-x-2">
        <span>Privacidad y Rastreo</span>
      </h4>

      <div className="bg-black border border-zinc-800 rounded-md p-6 relative overflow-hidden group">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Sección A: Datos de Rastreo */}
          <div className="relative">
            <PrivacyListSection 
              title="Datos de Rastreo" 
              icon={Eye} 
              items={tracking_used} 
              emptyMessage="Limpio de trackers publicitarios" 
            />
            {trackers_count > 5 && (
              <p className="text-[10px] text-orange-500/80 font-bold uppercase tracking-wider mt-3">Rastreo Intensivo Detectado</p>
            )}
          </div>

          {/* Sección B: Datos Vinculados */}
          <PrivacyListSection 
            title="Datos Vinculados" 
            icon={User} 
            items={data_linked} 
            emptyMessage="Sin recolección de identidad"
            dangerDotColor="bg-yellow-500/60"
          />

          {/* Sección C: Acceso a Dispositivos */}
          <PrivacyListSection 
            title="Acceso a Dispositivos" 
            icon={Camera} 
            items={device_access} 
            emptyMessage="Sin acceso detectado" 
          />

        </div>

        {/* Disclaimer final alineado a la izquierda */}
        <div className="mt-8 pt-4 border-t border-zinc-900/50">
          <p className="text-sm text-zinc-500 text-left leading-relaxed">
            Análisis basado en el comportamiento estático del código fuente. 
          </p>
        </div>
      </div>
    </div>
  );
}
