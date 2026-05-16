# PhishingScanner

[![Versión](https://img.shields.io/badge/versión-v1.0.0-blue)](#) [![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](#) [![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?logo=fastapi)](#) [![Docker](https://img.shields.io/badge/Docker-Soportado-2496ED?logo=docker)](#)

PhishingScanner es un ecosistema diseñado para detectar phishing y malware en URLs e imágenes. Combina OSINT, más de 90 motores antivirus y el razonamiento de GPT-4o-mini para transformar datos técnicos complejos en reportes claros e interactivos.

Actualmente soporta el análisis de:
* **URLs en vivo** (Renderizado *headless* y peticiones HTTP)
* **Imágenes** (Capturas de SMS o webs falsas)
* **Estructuras DOM** (Detección de robo de credenciales)
* **Red y Rastreadores** (DNS, WHOIS, SSL, Fingerprinting)

## Inicio Rápido

La vía recomendada para evitar conflictos de dependencias y aislar la red es usar Docker.

**1. Clonar y configurar:**
```bash
git clone https://github.com/ismael-vp/PhishingScanner.git
cd PhishingScanner
```

Crea los archivos `.env` (usa los `.example` como guía):
* `backend/.env`: Necesitas `VT_API_KEY`, `OPENAI_API_KEY`, `ADMIN_SECRET_KEY` y `ALLOWED_ORIGINS`. Opcionalmente `REDIS_URL` para caché distribuida y `ABUSEIPDB_API_KEY`.
* `frontend/.env`: Necesitas `NEXT_PUBLIC_API_URL` (por defecto `http://localhost:8000`).

**2. Levantar el ecosistema:**
```bash
docker-compose up --build
```
La interfaz estará disponible en `http://localhost:3000`.

*(Para desarrollo local manual: usa `npm run dev` en `/frontend` y `uvicorn main:app --reload` en `/backend`).*

## Arquitectura del Proyecto

El proyecto sigue una arquitectura cliente-servidor desacoplada, diseñada para escalar de forma independiente.

```text
PhishingScanner/
├── frontend/                 # Interfaz de usuario (Next.js 15, React, Tailwind)
│   ├── src/components/       # UI Reutilizable (Formularios, Tarjetas de resultados)
│   ├── src/features/         # Lógica específica de dominio (Análisis, Chat IA)
│   ├── src/store/            # Gestión del estado global (Zustand)
│   └── src/types/            # Definiciones de TypeScript e interfaces
├── backend/                  # Motor de análisis y API RESTful (FastAPI, Python)
│   ├── api/                  # Controladores y Endpoints expuestos al cliente
│   ├── services/             # Lógica core (Orquestador OSINT, Web Scrapers, IA)
│   ├── models/               # Esquemas de validación de datos (Pydantic)
│   ├── utils/cache_service.py# Sistema Dual de Caché Inteligente (Redis / SQLite)
│   └── threat_cache.db       # Caché embebida local (fallback de Redis)
└── docker-compose.yml        # Orquestación de contenedores y redes virtuales
```

## Consideraciones de Seguridad y Despliegue

* **Caché Inteligente e Inmutable (Redis + SQLite):** En producción el sistema utiliza **Redis (ej. Upstash)** con soporte de *fallback* automático a SQLite. Esto no solo evita agotar cuotas de las APIs (VirusTotal/OpenAI), sino que cuenta con un sistema antienvenenamiento que evita guardar análisis con fallos de API.
* **Endpoint de Limpieza:** Cuenta con la ruta protegida (`/api/admin/clear-cache`) gestionada por tu `ADMIN_SECRET_KEY` para purgar los servidores de caché instantáneamente de forma remota.
* **CORS y Autodefensa:** Modifica la variable `ALLOWED_ORIGINS` para que únicamente el dominio de tu frontend pueda realizar consultas. El sistema automáticamente neutraliza barras extra para garantizar protección exacta.
* **Plataformas:** 
  * Frontend optimizado para despliegue automático (Zero-config) en **Vercel**. 
  * Backend preparado para despliegue en contenedores vía **Render**, **Railway** o cualquier servidor **VPS**.
