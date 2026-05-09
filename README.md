# PhishingScanner

> Plataforma inteligente de detección de phising impulsada por OSINT, heurística estructurada e Inteligencia Artificial.

PhishingScanner es un ecosistema de  diseñado para analizar URLs e imágenes en busca de señales de phishing y malware. A través de la orquestación de servicios OSINT, motores antivirus y el razonamiento avanzado de GPT-4o-mini, el sistema transforma datos técnicos complejos en veredictos claros, tanto para usuarios finales como para analistas técnicos.

<!-- 📸 Nota para el desarrollador: Añade aquí una captura de pantalla del dashboard principal o un GIF mostrando un análisis en tiempo real.
Ejemplo: ![Demo PhishingScanner](./docs/demo.gif) -->

## Características Principales

- **Análisis Híbrido:** Combina el escaneo de más de 90 motores antivirus (vía VirusTotal) con un motor de heurística estructural propia.
- **Detección de Phishing Visual:** Capacidad de analizar capturas de pantalla de SMS, correos o webs sospechosas mediante modelos de visión IA.
- **Escudo de Formularios:** Analiza el DOM de las páginas para identificar formularios diseñados para el robo de credenciales, evaluando su comportamiento y el destino de los datos.
- **Resumen Ejecutivo por IA:** Sintetiza los datos técnicos en lenguaje natural, proporcionando explicaciones sencillas y pasos de acción claros.
- **Chat Interactivo (Analista IA):** Un asistente integrado que permite al usuario resolver dudas contextuales sobre el análisis recién realizado.
- **Caché Inteligente:** Almacenamiento local mediante SQLite para mitigar peticiones redundantes, acelerar tiempos de respuesta y optimizar el consumo de cuotas de APIs externas.

## 🛠️ Tecnologías Utilizadas

- **Frontend:** Next.js 15, Tailwind CSS, Zustand (gestión de estado), Lucide React, Axios.
- **Backend:** FastAPI (Python), Uvicorn, SQLite3, Pydantic, BeautifulSoup 4.
- **Servicios Externos:** OpenAI API (GPT-4o-mini), VirusTotal API, AbuseIPDB, Microlink.
- **Infraestructura:** Docker, Docker Compose.

## 🚀 Instalación y Ejecución

La forma más sencilla y recomendada de levantar el proyecto es utilizando Docker.

### Prerrequisitos
- [Docker](https://docs.docker.com/get-docker/) y Docker Compose instalados.
- [Node.js](https://nodejs.org/) v18+ (Solo si planeas correr el frontend fuera del contenedor).
- [Python](https://www.python.org/) 3.10+ (Solo si planeas correr el backend localmente).

### Pasos

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/tu-usuario/PhishingScanner.git](https://github.com/tu-usuario/PhishingScanner.git)
   cd PhishingScanner
Levantar el ecosistema (Docker):

Bash
docker-compose up --build

   La aplicación estará disponible en `http://localhost:3000` y la API en `http://localhost:8000`.

## ⚙️ Configuración (Variables de Entorno)

Antes de iniciar la aplicación, debes configurar las credenciales locales. Copia los archivos de ejemplo en sus respectivos directorios y rellena los valores.

**En `/backend/.env`:**
```env
VT_API_KEY=tu_api_key_de_virustotal
OPENAI_API_KEY=tu_api_key_de_openai
ALLOWED_ORIGINS=http://localhost:3000,[https://tu-dominio.com](https://tu-dominio.com)
En /frontend/.env:

Fragmento de código
NEXT_PUBLIC_API_URL=http://localhost:8000
💻 Desarrollo Local (Sin Docker)
Si prefieres levantar los servicios individualmente para depuración rápida:

Backend (Terminal 1):

Bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
Frontend (Terminal 2):

Bash
cd frontend
npm install
npm run dev
📖 Uso
Modo URL: Accede a la interfaz y pega cualquier enlace sospechoso. El sistema devolverá un reporte que incluye análisis estructural, reputación de IPs/dominios y el dictamen de la IA.

Modo Imagen: Selecciona la pestaña de imagen y sube una captura (ej. un SMS sospechoso). El motor de visión extraerá el texto y el contexto para determinar el riesgo.

Gestión de Caché (Admin): Para forzar la actualización de los reportes, purga la caché enviando una petición POST a /api/admin/clear-cache.

📂 Estructura del Proyecto
Plaintext
PhishingScanner/
├── frontend/                 # Aplicación cliente (Next.js)
│   ├── src/components/       # Componentes de UI modulares
│   ├── src/features/         # Lógica específica del dominio
│   └── src/store/            # Estado global (Zustand)
├── backend/                  # API RESTful (FastAPI)
│   ├── services/             # Integraciones (OSINT, OpenAI, VT)
│   ├── models/               # Esquemas de Pydantic
│   ├── utils/                # Funciones auxiliares
│   └── threat_cache.db       # BBDD local (SQLite)
├── docker-compose.yml        # Orquestación de contenedores
└── README.md

 Despliegue (Deployment)
La arquitectura está diseñada para un despliegue ágil en plataformas modernas:

Frontend: Optimizado para un despliegue sin fricción en Vercel. Simplemente conecta el repositorio e inyecta la variable NEXT_PUBLIC_API_URL.

Backend: Contenerizado con Docker. Preparado para desplegarse fácilmente en Render, Railway, o cualquier VPS (DigitalOcean, AWS EC2).

Seguridad (CORS): En producción, asegúrate de actualizar la variable ALLOWED_ORIGINS en el backend para admitir únicamente peticiones desde el dominio donde alojes el frontend.
