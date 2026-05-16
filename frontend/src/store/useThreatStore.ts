import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { ScanMode, ScanResult } from '@/types';
import { ScanResultSchema } from '@/lib/validations';


interface ThreatState {
  // Estado
  mode: ScanMode;
  isScanning: boolean;
  scanResult: ScanResult | null;
  error: string | null;
  history: ScanResult[];

  // Acciones
  setMode: (mode: ScanMode) => void;
  setIsScanning: (isScanning: boolean) => void;
  setScanResult: (result: ScanResult | null, resourceName?: string) => void;
  setError: (error: string | null) => void;
  resetState: () => void;
  clearHistory: () => void;
}

// -----------------------------------------------------------------------------
// Zustand Store con Persistencia (LocalStorage)
// -----------------------------------------------------------------------------

export const useThreatStore = create<ThreatState>()(
  persist(
    (set) => ({
      // Valores iniciales
      mode: 'url',
      isScanning: false,
      scanResult: null,
      error: null,
      history: [],

      // Setters
      setMode: (mode) => set({ mode }),
      setIsScanning: (isScanning) => set({ isScanning }),
      setScanResult: (result, resourceName) => 
        set((state) => {
          if (!result) return { scanResult: null, error: null };

          // --- VALIDACIÓN CON ZOD ---
          const validation = ScanResultSchema.safeParse(result);
          if (!validation.success) {
            console.error("Error de validación en los datos de la API:", validation.error);
            // Podríamos decidir si mostrar el error o continuar con los datos crudos
          }

          const validatedData = validation.success ? validation.data : result;

          // Bug #4 fix: normalizar resourceName antes del deduplicado
          const normalizedName = resourceName
            || validatedData.resourceName
            || (validatedData.type === 'url' ? 'URL Desconocida' : 'Archivo Analizado');

          // Enriquecemos el resultado con nombre y fecha para el historial
          const enrichedResult: ScanResult = {
            ...validatedData,
            resourceName: normalizedName,
            timestamp: new Date().toISOString()
          } as ScanResult;

          // Evitar duplicados consecutivos exactamente iguales y limitar a 10 escaneos
          const newHistory = [
            enrichedResult,
            ...state.history.filter(h => h.resourceName !== normalizedName)
          ].slice(0, 10);

          return { 
            scanResult: enrichedResult, 
            error: null,
            history: newHistory
          };
        }),
      setError: (error) => set({ error, scanResult: null, isScanning: false }),
      resetState: () => set({ isScanning: false, scanResult: null, error: null }),
      clearHistory: () => set({ history: [] }),
    }),
    {
      name: 'threat-history-storage',
      // Solo guardamos en localStorage la parte del historial, pero limpiamos campos pesados
      // como el contenido HTML para evitar QuotaExceededError.
      partialize: (state) => ({ 
        history: state.history.map(item => ({
          ...item,
          osint_data: item.osint_data ? {
            ...item.osint_data,
            html_content: "", // El HTML es muy pesado para el historial
            screenshot_desktop: "", // Las imágenes Base64 saturan el LocalStorage
            screenshot_mobile: "",
          } : null
        }))
      }), 
    }
  )
);
