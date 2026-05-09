import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="w-full max-w-2xl mx-auto mt-8 bg-[#1a0505] border border-red-900/50 p-6 rounded-lg flex flex-col items-center justify-center text-center">
          <AlertTriangle className="text-red-600 mb-4" size={48} />
          <h2 className="text-xl font-bold text-[#ededed] mb-2">Algo salió mal en la interfaz</h2>
          <p className="text-sm text-[#888] mb-6">
            Se produjo un error crítico al intentar renderizar este componente.
            Por favor, recarga la página o inténtalo de nuevo.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="flex items-center space-x-2 bg-red-600 hover:bg-red-700 transition-colors text-white text-sm font-medium py-2 px-4 rounded-md"
          >
            <RotateCcw size={16} />
            <span>Recargar Página</span>
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
