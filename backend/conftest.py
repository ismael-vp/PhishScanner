"""
conftest.py — raíz de backend/

Añade el directorio backend/ al sys.path para que pytest pueda importar
los módulos del proyecto (services, utils, models, etc.) sin necesidad
de instalarlos como paquete.
"""
import sys
import os

# Garantiza que `backend/` sea el directorio raíz de imports
sys.path.insert(0, os.path.dirname(__file__))
