import os
import json
from fastapi import HTTPException
from utils.openai_client import get_openai_client

class AIService:
    def __init__(self):
        self.client = get_openai_client()

    async def generate_analysis_explanation(self, vt_stats: dict, resource_type: str) -> str:
        """
        Recibe las estadísticas de VirusTotal y genera una explicación
        en lenguaje natural utilizando GPT-4o-mini.
        
        :param vt_stats: Diccionario con {malicious, undetected, etc.}
        :param resource_type: String indicando si es 'url' o 'archivo'
        :return: Texto con la explicación (máx 2 párrafos).
        """
        if not self.client:
            raise HTTPException(status_code=500, detail="La API Key de OpenAI no está configurada.")

        # Calculamos el total de alertas (maliciosos + sospechosos) para que la IA
        # utilice exactamente el mismo número que muestra el banner de la interfaz.
        total_alerts = vt_stats.get('malicious', 0) + vt_stats.get('suspicious', 0)

        # Convertimos las estadísticas a string formateado
        stats_str = json.dumps(vt_stats, indent=2)

        system_prompt = (
            "Eres un analista experto en ciberseguridad. Tu tarea es interpretar métricas de detección "
            "de motores antivirus y explicar a un usuario sin conocimientos técnicos avanzados "
            "si el recurso analizado es seguro o peligroso.\n\n"
            "REGLAS ESTRICTAS:\n"
            "1. Tu respuesta debe ser estrictamente un objeto JSON.\n"
            "2. El JSON debe tener exactamente esta estructura: "
            '{"summary": "Resumen ejecutivo en 1 o 2 oraciones máximo.", "action_steps": ["Paso 1", "Paso 2", "Paso 3"]}.\n'
            f"3. IMPORTANTE: Debes basar tu resumen en que hay exactamente {total_alerts} motores que han levantado "
            "alertas en total (maliciosos + sospechosos combinados).\n"
            "4. En 'summary', sé extremadamente conciso, directo y técnico (estilo informe ejecutivo). "
            "Ejemplo ideal: 'El consenso de X motores de seguridad (incluyendo Kaspersky) clasifica esta URL como una amenaza de phishing. Adicionalmente, el análisis heurístico detecta patrones de comportamiento evasivo que confirman el riesgo.' "
            "Evita usar palabras de relleno. Si el enlace es seguro, simplemente indica que no hay motores que hayan detectado problemas de seguridad.\n"
            "5. En 'action_steps', genera máximo 3 pasos ultracortos y directos (ej. 'Evitar cualquier interacción con la URL.', 'Bloquear el dominio en los filtros de red.')."
        )

        user_prompt = (
            f"El recurso escaneado es un(a): {resource_type}.\n\n"
            f"Total de motores que han levantado alertas (maliciosos + sospechosos): {total_alerts}.\n\n"
            f"Estadísticas completas de detección:\n{stats_str}"
        )

        try:
            # Llamada asíncrona al modelo especificado
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3, # Temperatura baja para mantener un tono consistente y analítico
                max_tokens=400
            )
            
            content = response.choices[0].message.content.strip()
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"summary": content, "action_steps": []}
            
        except Exception as e:
            raise HTTPException(
                status_code=500, 
                detail=f"Hubo un problema al generar el análisis de la IA: {str(e)}"
            )

    async def chat_with_context(self, messages: list, scan_context: dict) -> str:
        """
        Responde a preguntas del usuario basándose en el historial de chat y el JSON del escaneo.
        """
        if not self.client:
            raise HTTPException(status_code=500, detail="La API Key de OpenAI no está configurada.")

        context_str = json.dumps(scan_context, indent=2)
        system_prompt = (
            "Eres un analista experto en ciberseguridad. Responde a la duda del usuario basándote "
            f"exclusivamente en los siguientes datos del escaneo:\n{context_str}\n\n"
            "Sé conciso, profesional y directo. No inventes datos que no estén en el escaneo."
        )

        formatted_messages = [{"role": "system", "content": system_prompt}] + messages

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=formatted_messages,
                temperature=0.3,
                max_tokens=300
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al comunicar con la IA en el chat: {str(e)}")

    async def explain_script(self, script_url: str) -> str:
        """
        Explica de forma sencilla qué hace un script web basándose en su URL.
        """
        if not self.client:
            raise HTTPException(status_code=500, detail="La API Key de OpenAI no está configurada.")

        system_prompt = (
            "Eres un experto en ciberseguridad. Te darán la URL de un script o rastreador web. "
            "Explica en español, de forma muy sencilla, breve (máximo 2 párrafos) y sin tecnicismos técnicos qué hace este script normalmente. "
            "Si es algo común y seguro (como jQuery, Google Analytics o un CDN), tranquiliza al usuario. "
            "Si parece sospechoso o no común, adviértelo."
        )

        user_prompt = f"Explica este script: {script_url}"

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=300
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al analizar el script: {str(e)}")

