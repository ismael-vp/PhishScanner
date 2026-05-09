# PhishingScanner

[![version v1.0.0](https://img.shields.io/badge/pypi-v1.0.0-orange)](#) [![downloads](https://img.shields.io/badge/downloads-1k/day-brightgreen)](#) [![Built by](https://img.shields.io/badge/Built%20by-Security%20Team-blue)](#)

> **Importante**
>
> PhishingScanner interactúa con URLs potencialmente maliciosas, dominios activos y servicios de inteligencia de amenazas de terceros. Al igual que cualquier herramienta de análisis de seguridad, accede a recursos a través de la red basándose en la entrada del usuario. Sanitiza tus entradas en entornos no confiables, nunca hagas clic en enlaces maliciosos directamente desde tu máquina host y asegúrate de que tus claves API (VirusTotal, OpenAI) estén estrictamente protegidas. Consulta la sección de Consideraciones de Seguridad en la documentación para más información.

PhishingScanner es un ecosistema híbrido de detección de amenazas web para analizar URLs e imágenes con el fin de identificar phishing y malware. En este sentido, es comparable a los feeds tradicionales de inteligencia de amenazas, pero con un enfoque en la orquestación de servicios OSINT, motores antivirus y el razonamiento avanzado de LLMs (GPT-4o-mini) para proporcionar veredictos claros y procesables. Aunque el resultado técnico es muy detallado para los analistas de seguridad, está diseñado para ser consumido y comprendido fácilmente por los usuarios finales.

PhishingScanner actualmente soporta el análisis de:
* URLs activas (vía peticiones HTTP y renderizado *headless*)
* Imágenes (capturas de pantalla de SMS, correos electrónicos o sitios de phishing)
* Estructuras DOM (detección de robo de credenciales en formularios)
* Indicadores de red (DNS, WHOIS, SSL)
* Vectores de rastreo y *fingerprinting*

## ¿Por qué PhishingScanner?

Los escáneres tradicionales proporcionan datos técnicos en bruto (respuestas JSON, puntuaciones de reputación de IP) que son difíciles de interpretar para usuarios no técnicos. Los LLMs convencionales, como GPT-4o de OpenAI, son excelentes razonando sobre datos estructurados. PhishingScanner aprovecha esto integrando más de 90 motores antivirus y heurísticas estructurales propietarias en un resumen unificado impulsado por IA, actuando efectivamente como un Analista de Seguridad de Nivel 1 automatizado. Como beneficio adicional, almacena los resultados en caché localmente para ser altamente eficiente con los tokens de las APIs.

## Requisitos Previos

PhishingScanner requiere **Docker** para un despliegue más sencillo. Si deseas ejecutar los servicios localmente sin contenedores, requiere **Python 3.10** o superior y **Node.js 18** o superior.

Se recomienda utilizar Docker para evitar conflictos de dependencias y garantizar el aislamiento de la red al escanear objetivos maliciosos.

## Instalación

Para instalar y ejecutar PhishingScanner, se recomienda clonar el código fuente:

```bash
git clone [https://github.com/tu-usuario/PhishingScanner.git](https://github.com/tu-usuario/PhishingScanner.git)
cd PhishingScanner
Crea los archivos de entorno necesarios basándote en los ejemplos proporcionados:

Backend (backend/.env):

Fragmento de código
VT_API_KEY=<tu_api_key_de_virustotal>
OPENAI_API_KEY=<tu_api_key_de_openai>
ALLOWED_ORIGINS=http://localhost:3000
Frontend (frontend/.env):

Fragmento de código
NEXT_PUBLIC_API_URL=http://localhost:8000
Uso
Docker (Recomendado)
Para construir y ejecutar todo el ecosistema (Frontend, Backend y la caché local en SQLite) en un entorno contenerizado:

Bash
docker-compose up --build
Abre http://localhost:3000 en tu navegador para acceder a la interfaz.

Desarrollo Local
Si prefieres ejecutar los componentes individualmente para depuración:

1. Iniciar la API (Backend):

Bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
2. Iniciar la Interfaz (Frontend):

Bash
cd frontend
npm install
npm run dev
Uso de la API
Puedes interactuar directamente con el backend de PhishingScanner a través de su API REST. Uso básico para escanear una URL:

Bash
curl -X POST http://localhost:8000/api/analyze/url \
     -H "Content-Type: application/json" \
     -d '{"url": "[https://enlace-sospechoso.com](https://enlace-sospechoso.com)"}'
Arquitectura y Estructura
El repositorio se divide en dos componentes principales:

frontend/: La aplicación cliente en Next.js 15, que utiliza Tailwind CSS y Zustand para la gestión del estado.

backend/: La aplicación en Python con FastAPI, que contiene services/ (integración OSINT, OpenAI, VT) y la base de datos local threat_cache.db.

Cómo Contribuir
Este proyecto agradece las contribuciones y sugerencias. Cuando envíes un pull request, asegúrate de que tu código siga la arquitectura existente (por ejemplo, separando las tareas intensivas de CPU del bucle de eventos asyncio).

Cualquier issue o PR es bienvenido, pero también hemos marcado algunos como 'abiertos para contribución' para facilitar la participación de la comunidad. Puedes ayudar revisando issues, añadiendo nuevos módulos heurísticos OSINT o revisando PRs.

Consideraciones de Seguridad
PhishingScanner realiza operaciones de red de E/S y gestiona claves API confidenciales.

Sanitiza tus entradas: No expongas el backend de PhishingScanner a Internet público sin un límite de peticiones (rate limiting) y validación de entrada adecuados.

Configuración CORS: La variable de entorno ALLOWED_ORIGINS en el backend dicta qué dominios pueden interactuar con la API. Para despliegues en producción, asegúrate de que esté configurada estrictamente con el dominio de tu frontend.

Protección de Claves API: La herramienta depende de APIs de terceros de pago o medidas por uso. La caché SQLite integrada mitiga las llamadas repetitivas, pero debes monitorear tus paneles de uso de VirusTotal y OpenAI para evitar el agotamiento de la cuota por solicitudes abusivas.

Despliegue
La arquitectura está diseñada para un despliegue ágil en plataformas modernas. El Frontend está optimizado para un despliegue sin fricción en Vercel (inyectando la variable NEXT_PUBLIC_API_URL). El Backend está contenerizado y listo para desplegarse en Render, Railway o cualquier entorno VPS con Linux.
