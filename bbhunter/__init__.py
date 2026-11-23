"""BBHunter: asistente semi-automatico de bug bounty.

Automatiza recon, escaneo, enriquecimiento (CVSS/VRT + Claude) y generacion de
informes. La VALIDACION y el ENVIO de reportes son SIEMPRE manuales por diseno:
las plataformas prohiben el escaneo no autorizado y el envio automatico de
reportes sin validar. Opera unicamente dentro del scope autorizado.
"""

__version__ = "0.1.0"
