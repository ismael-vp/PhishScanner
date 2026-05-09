import io
import json
import re
import os
from fastapi import HTTPException
from utils.openai_client import get_openai_client

# pytesseract wraps the Tesseract OCR binary (installed separately).
# We import it lazily so startup doesn't fail if not yet installed.
_tesseract_ready: bool | None = None


def _ensure_tesseract():
    """Verifies that pytesseract + the Tesseract binary are available."""
    global _tesseract_ready
    if _tesseract_ready is True:
        return
    try:
        import pytesseract
        # Common Windows install path for UB-Mannheim's Tesseract installer
        default_win_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if os.name == "nt" and os.path.exists(default_win_path):
            pytesseract.pytesseract.tesseract_cmd = default_win_path
        # Quick smoke-test — raises if binary is not found
        pytesseract.get_tesseract_version()
        _tesseract_ready = True
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Tesseract OCR no está instalado o no se encuentra. "
                "Instálalo con: winget install --id UB-Mannheim.TesseractOCR "
                f"| Detalle técnico: {exc}"
            ),
        )


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract URL-like strings from OCR text."""
    url_pattern = re.compile(
        r"(?i)\b(?:https?://|www\.)[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/))",
        re.IGNORECASE,
    )
    # Use a set comprehension for unique urls
    seen: set[str] = set()
    urls: list[str] = []
    for match in url_pattern.finditer(text):
        u = match.group(0).strip(".,;:!?\"'()")
        if len(u) > 5 and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


class ImagePhishingService:
    def __init__(self):
        self.client = get_openai_client()

    def extract_text_from_image(self, image_bytes: bytes) -> str:
        """Use pytesseract to extract text from image bytes."""
        _ensure_tesseract()
        import pytesseract
        from PIL import Image

        try:
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            # Use Spanish + English; PSM 6 = uniform block of text (good for SMS/email screenshots)
            custom_config = r"--oem 3 --psm 6 -l spa+eng"
            text = pytesseract.image_to_string(img, config=custom_config)
            return text.strip()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=422,
                detail=f"No se pudo procesar la imagen con OCR: {str(e)}"
            )

    async def analyze_for_phishing(self, image_bytes: bytes) -> dict:
        """
        Full pipeline: OCR → GPT-4o-mini phishing analysis.
        Returns a structured dict with verdict, confidence, red_flags, etc.
        """
        if not self.client:
            raise HTTPException(
                status_code=500,
                detail="La API Key de OpenAI no está configurada."
            )

        # Step 1: Extract text with OCR
        extracted_text = self.extract_text_from_image(image_bytes)

        if not extracted_text or len(extracted_text.strip()) < 10:
            return {
                "is_phishing": False,
                "confidence": "Baja",
                "verdict": "No se pudo extraer texto suficiente de la imagen. Asegúrate de que la imagen sea nítida y contenga texto visible.",
                "red_flags": [],
                "extracted_text": extracted_text or "",
                "extracted_urls": [],
            }

        # Step 2: Extract URLs from raw OCR text
        extracted_urls = _extract_urls_from_text(extracted_text)

        # Step 3: Analyze with gpt-4o-mini
        system_prompt = (
            "Eres un experto en ciberseguridad especializado en detectar phishing en mensajes de texto (SMS), "
            "correos electrónicos y capturas de pantalla. El usuario te proporcionará el texto extraído "
            "mediante OCR de una captura de pantalla de un mensaje.\n\n"
            "Tu tarea es analizar el texto y determinar si es un intento de phishing o no.\n\n"
            "Señales de phishing a buscar:\n"
            "- Urgencia artificial ('Tu cuenta será bloqueada', 'Actúa ahora', 'En las próximas 24 horas')\n"
            "- Solicitudes de datos personales, contraseñas, datos bancarios o números de tarjeta\n"
            "- URLs sospechosas (dominios extraños, acortadores de URL, imitaciones de marcas)\n"
            "- Remitentes falsos o números desconocidos que suplantan a bancos, Correos, BBVA, Hacienda, etc.\n"
            "- Errores ortográficos o gramaticales graves en mensajes supuestamente oficiales\n"
            "- Premios, herencias o recompensas inesperadas\n"
            "- Amenazas de consecuencias graves si no se actúa\n\n"
            "REGLAS ESTRICTAS:\n"
            "1. Tu respuesta debe ser ESTRICTAMENTE un objeto JSON válido.\n"
            "2. Estructura exacta requerida:\n"
            '{"is_phishing": true/false, "confidence": "Alta|Media|Baja", '
            '"verdict": "Tu explicación en 1-2 frases claras para el usuario", '
            '"red_flags": ["Señal 1 encontrada", "Señal 2 encontrada"]}\n'
            "3. 'confidence' debe reflejar qué tan seguro estás: Alta (>80%), Media (50-80%), Baja (<50%).\n"
            "4. Si no hay suficiente texto o el mensaje parece legítimo, devuelve is_phishing: false.\n"
            "5. Responde siempre en ESPAÑOL."
        )

        user_prompt = (
            f"Analiza este texto extraído de una captura de pantalla:\n\n"
            f"---\n{extracted_text}\n---\n\n"
            f"URLs detectadas en el texto: {', '.join(extracted_urls) if extracted_urls else 'ninguna'}"
        )

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=400,
            )

            content = response.choices[0].message.content.strip()
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = {
                    "is_phishing": False,
                    "confidence": "Baja",
                    "verdict": content,
                    "red_flags": [],
                }

            parsed["extracted_text"] = extracted_text
            parsed["extracted_urls"] = extracted_urls
            return parsed

        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error al analizar la imagen con la IA: {str(e)}"
            )
