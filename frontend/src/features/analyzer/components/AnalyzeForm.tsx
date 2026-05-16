"use client";

import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { useThreatStore } from '@/store/useThreatStore';
import { Link, Search, X, Trash2, ScanLine } from 'lucide-react';
import { API_URL } from '@/lib/api';

export default function AnalyzeForm() {
  const { mode, setMode, setIsScanning, setScanResult, setError, isScanning, error } = useThreatStore();
  const [urlInput, setUrlInput] = useState('');
  const [imageInput, setImageInput] = useState<File | null>(null);
  const [loadingMessage, setLoadingMessage] = useState('Iniciando análisis...');

  // 1. NUEVO ESTADO: Para guardar la URL segura de la imagen
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  // 2. NUEVA REFERENCIA: Para cancelar peticiones HTTP duplicadas (Race Conditions)
  const abortControllerRef = useRef<AbortController | null>(null);

  // --- EFECTO: Gestor de Memoria para la previsualización de imágenes (Fix Blob Leak) ---
  useEffect(() => {
    if (!imageInput) {
      setPreviewUrl(null);
      return;
    }

    // Crea la URL temporal en la memoria del navegador
    const objectUrl = URL.createObjectURL(imageInput);
    setPreviewUrl(objectUrl);

    // CLEANUP FUNCTION: Se ejecuta cuando imageInput cambia o el componente se desmonta.
    // Esto libera la RAM del navegador inmediatamente.
    return () => {
      URL.revokeObjectURL(objectUrl);
    };
  }, [imageInput]);


  // --- EFECTO: Gestor de mensajes de carga ---
  useEffect(() => {
    if (!isScanning) return;
    const messages = mode === 'url'
      ? ['Analizando estructura...', 'Consultando motores...', 'Sintetizando veredicto...']
      : ['Extrayendo texto...', 'Analizando contenido...', 'Generando reporte...'];

    let i = 0;
    const interval = setInterval(() => {
      setLoadingMessage(messages[i % messages.length]);
      i++;
    }, 3000);

    return () => clearInterval(interval);
  }, [isScanning, mode]);


  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // 3. CANCELACIÓN DE PETICIONES (Fix Race Condition)
    // Si ya había un escaneo en curso y el usuario lanza otro, cancelamos el anterior
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    // Instanciamos un nuevo controlador para esta petición
    abortControllerRef.current = new AbortController();

    setError(null);
    setIsScanning(true);
    setScanResult(null);

    try {
      if (mode === 'url') {
        if (!urlInput) {
          setError("Por favor, introduce una URL válida para analizar.");
          setIsScanning(false);
          return;
        }

        // Pasamos el signal del AbortController a Axios
        const response = await axios.post(`${API_URL}/api/analyze/url`,
          { url: urlInput },
          { signal: abortControllerRef.current.signal }
        );
        setScanResult(response.data, urlInput);

      } else if (mode === 'image') {
        if (!imageInput) {
          setError("Por favor, selecciona una imagen para analizar.");
          setIsScanning(false);
          return;
        }
        const formData = new FormData();
        formData.append('file', imageInput);

        // Pasamos el signal a la subida de imagen
        const response = await axios.post(`${API_URL}/api/analyze/image`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
          signal: abortControllerRef.current.signal
        });
        setScanResult(response.data, imageInput.name);
      }
    } catch (err: unknown) {
      // Manejamos el caso en que la petición fue cancelada intencionalmente
      if (axios.isCancel(err) || abortControllerRef.current?.signal.aborted) {
        console.log("Petición anterior cancelada para evitar sobreescritura de datos.");
        return;
      }

      if (axios.isAxiosError(err) && err.response && err.response.data && err.response.data.detail) {
        const detail = err.response.data.detail;

        const toUserMessage = (raw: string): string => {
          // Eliminar el prefijo técnico que añade Pydantic v2
          const clean = raw.replace(/^Value error,\s*/i, '').trim();
          // Normalizar mensajes técnicos de seguridad a texto amigable
          if (clean.toLowerCase().includes('ssrf') || clean.toLowerCase().includes('no es segura')) {
            return 'La URL introducida no es válida o no se puede analizar.';
          }
          if (clean.toLowerCase().includes('dominio válido') || clean.toLowerCase().includes('netloc')) {
            return 'La URL no contiene un dominio válido. Asegúrate de incluir el protocolo (https://...).';
          }
          if (clean.toLowerCase().includes('http') && clean.toLowerCase().includes('protocolo')) {
            return 'La URL debe empezar por https:// o http://.';
          }
          return clean;
        };

        if (Array.isArray(detail)) {
          const firstError = detail[0];
          setError(toUserMessage(firstError.msg || 'Error de validación en los datos enviados.'));
        } else {
          setError(toUserMessage(String(detail)));
        }
      } else {
        setError('Error de conexión con el servidor. ¿Está el backend encendido?');
      }
    } finally {
      // Fix Caos #4: solo desactivar el estado de carga si esta petición no ha sido abortada
      // por una nueva petición que ya ha tomado el control.
      if (!abortControllerRef.current?.signal.aborted) {
        setIsScanning(false);
      }
    }
  };


  return (
    <div className="w-full max-w-5xl mx-auto bg-black border border-[#333] p-6 rounded-lg shadow-sm">
      {/* Selector de Pestañas */}
      <div className="flex space-x-6 border-b border-[#333] mb-8">
        <button
          type="button"
          onClick={() => setMode('url')}
          className={`pb-3 text-sm font-medium transition-colors flex items-center space-x-2 relative ${mode === 'url' ? 'text-[#ededed]' : 'text-[#888] hover:text-[#ededed]'
            }`}
        >
          <Link size={16} />
          <span>Analizar URL</span>
          {mode === 'url' && (
            <span className="absolute bottom-[-1px] left-0 w-full h-[1px] bg-white"></span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setMode('image')}
          className={`pb-3 text-sm font-medium transition-colors flex items-center space-x-2 relative ${mode === 'image' ? 'text-[#ededed]' : 'text-[#888] hover:text-[#ededed]'
            }`}
        >
          <ScanLine size={16} />
          <span>Analizar imagen</span>
          {mode === 'image' && (
            <span className="absolute bottom-[-1px] left-0 w-full h-[1px] bg-white"></span>
          )}
        </button>
      </div>

      {/* Formulario Principal */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {mode === 'url' ? (
          <div className="space-y-2">
            <label htmlFor="url" className="text-sm text-[#ededed] font-medium block">
              Enlace a analizar
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search size={16} className="text-[#888]" />
              </div>
              <input
                id="url"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://pagina-peligrosa.com"
                className="w-full bg-black border border-[#333] text-[#ededed] placeholder-[#888] text-sm rounded-md py-3 pl-10 pr-10 focus:outline-none focus:ring-1 focus:ring-white transition-shadow"
                disabled={isScanning}
              />
              {urlInput && !isScanning && (
                <button
                  type="button"
                  onClick={() => setUrlInput('')}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#666] hover:text-white transition-colors"
                >
                  <X size={16} />
                </button>
              )}
            </div>
          </div>
        ) : (
          /* mode === 'image' */
          <div className="space-y-2">
            <label className="text-sm text-[#ededed] font-medium block">
              Captura de pantalla
            </label>
            <p className="text-xs text-[#888] mb-3">
              Sube una captura de un SMS, email o página web. Extraeremos el texto para comprobar si es seguro.
            </p>
            <div className="flex items-center justify-center w-full">
              <label
                htmlFor="dropzone-image"
                className="flex flex-col items-center justify-center w-full h-40 border border-[#333] border-dashed rounded-md cursor-pointer bg-black hover:bg-[#111] transition-colors"
              >
                {previewUrl ? (
                  <div className="relative w-full h-full">
                    {/* 4. USO DE LA URL SEGURA (El src apunta al estado, no genera la URL directamente) */}
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={previewUrl}
                      alt="Vista previa"
                      className="w-full h-full object-contain rounded-md p-2"
                    />
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        setImageInput(null);
                      }}
                      className="absolute top-2 right-2 flex items-center space-x-1 text-xs text-red-400 hover:text-red-300 bg-black/80 border border-red-900/50 px-2 py-1 rounded transition-colors"
                    >
                      <Trash2 size={12} />
                      <span>Eliminar</span>
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center pt-5 pb-6">
                    <ScanLine size={24} className="mb-2 text-[#888]" />
                    <p className="mb-1 text-sm text-[#ededed]">
                      <span className="font-semibold">Haz clic para subir</span> o arrastra aquí
                    </p>
                    <p className="text-xs text-[#888]">JPG, PNG, WEBP — Máx. 10MB</p>
                  </div>
                )}
                <input
                  id="dropzone-image"
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(e) => setImageInput(e.target.files ? e.target.files[0] : null)}
                  disabled={isScanning}
                />
              </label>
            </div>
          </div>
        )}

        <div className="pt-2">
          <button
            type="submit"
            disabled={isScanning || (mode === 'url' ? !urlInput : !imageInput)}
            className={`w-full flex items-center justify-center space-x-2 bg-white text-black font-medium py-3 rounded-md text-sm transition-all hover:bg-zinc-200 disabled:bg-zinc-900 disabled:text-zinc-500 ${isScanning ? 'cursor-wait' : 'disabled:cursor-not-allowed'
              }`}
          >
            {isScanning ? (
              <div className="flex items-center space-x-3">
                <div className="flex space-x-1.5">
                  <div className="w-1.5 h-1.5 bg-zinc-400 rounded-full animate-dot-jump"></div>
                  <div className="w-1.5 h-1.5 bg-zinc-400 rounded-full animate-dot-jump delay-200"></div>
                  <div className="w-1.5 h-1.5 bg-zinc-400 rounded-full animate-dot-jump delay-400"></div>
                </div>
                <span className="text-zinc-400 font-normal">Analizando</span>
              </div>
            ) : (
              <span>
                {mode === 'image' ? 'Analizar imagen' : 'Iniciar análisis'}
              </span>
            )}
          </button>

          {isScanning && (
            <p className="text-center text-[10px] text-zinc-600 mt-4 uppercase tracking-widest animate-pulse">
              {loadingMessage}
            </p>
          )}

          {!isScanning && (
            <p className="text-center text-xs text-zinc-500 mt-4">
              Impulsado por GPT-4o-mini y VirusTotal.
            </p>
          )}
        </div>
      </form>
    </div>
  );
}