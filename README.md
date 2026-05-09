PhishingScanner
Plataforma inteligente de detección de phishing impulsada por OSINT, heurística estructurada e IA.

PhishingScanner analiza URLs e imágenes para detectar amenazas web. Orquesta múltiples servicios de seguridad y utiliza GPT-4o-mini para traducir análisis técnicos complejos en veredictos claros e interactivos.

✨ Características Principales
Análisis Híbrido: Integra más de 90 motores antivirus (VirusTotal) con heurística propia (análisis de DOM y formularios).

Inspección Visual (IA): Detecta engaños en capturas de pantalla, correos o SMS.

Analista IA Integrado: Chat contextual para resolver dudas sobre el reporte generado.

Alta Eficiencia: Caché en SQLite para reducir tiempos de respuesta y ahorrar cuotas de API.

🛠️ Stack Tecnológico
Frontend: Next.js 15, Tailwind CSS, Zustand.

Backend: FastAPI (Python), SQLite3, Pydantic, BeautifulSoup 4.

Servicios: OpenAI, VirusTotal, AbuseIPDB, Microlink.

Infraestructura: Docker & Docker Compose.

🚀 Inicio Rápido
La forma más rápida de ejecutar el proyecto es usando Docker.

1. Clonar y configurar:

Bash
git clone https://github.com/tu-usuario/PhishingScanner.git
cd PhishingScanner
Crea los archivos de entorno basándote en los .example:

Fragmento de código
# /backend/.env
VT_API_KEY=tu_api_key
OPENAI_API_KEY=tu_api_key
ALLOWED_ORIGINS=http://localhost:3000

# /frontend/.env
NEXT_PUBLIC_API_URL=http://localhost:8000
2. Levantar servicios:

Bash
docker-compose up --build
Frontend activo en http://localhost:3000 | API activa en http://localhost:8000

(Nota: Para desarrollo local sin Docker, ejecuta npm run dev en /frontend y uvicorn main:app --reload en /backend).

📖 Uso
Escaneo: Pega una URL o sube una imagen desde la interfaz para obtener el dictamen.

Limpieza de Caché: Envía una petición POST a /api/admin/clear-cache para forzar análisis nuevos.

📂 Estructura Resumida
PhishingScanner/
├── frontend/                 
│   ├── src/components/       
│   ├── src/features/         
│   └── src/store/            
├── backend/                  
│   ├── services/
│   ├── models/               
│   ├── utils/                
│   └── threat_cache.db       
├── docker-compose.yml        
└── README.md


Backend: Contenerizado para Render, Railway o cualquier VPS.

Seguridad: En producción, asegúrate de configurar ALLOWED_ORIGINS para proteger tu API.
