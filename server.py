import os
import base64
import httpx
from typing import Optional, Dict, Any, Union
from fastmcp import FastMCP
from dotenv import load_dotenv

# Configuración inicial
load_dotenv()
mcp = FastMCP("VirusTotal MCP")
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

if not API_KEY:
    raise ValueError("Error: La variable de entorno VIRUSTOTAL_API_KEY es obligatoria.")

class VirusTotalHelper:
    """
    Clase auxiliar para manejar la lógica de conexión y formateo
    de respuestas de la API de VirusTotal.
    """
    
    @staticmethod
    def get_headers() -> Dict[str, str]:
        return {
            "x-apikey": API_KEY,
            "Accept": "application/json"
        }

    @staticmethod
    def format_stats(stats: Dict[str, int]) -> str:
        """Formatea las estadísticas de análisis en una cadena legible."""
        return (
            f"Malicioso: {stats.get('malicious', 0)} | "
            f"Sospechoso: {stats.get('suspicious', 0)} | "
            f"Inofensivo: {stats.get('harmless', 0)} | "
            f"No detectado: {stats.get('undetected', 0)}"
        )

    @staticmethod
    def format_response(data: Dict[str, Any], resource_type: str) -> str:
        """
        Procesa el JSON crudo de VT y devuelve un resumen estructurado.
        """
        try:
            attrs = data.get("data", {}).get("attributes", {})
            if not attrs:
                return "No se encontraron atributos detallados en la respuesta."

            # Extracción de campos comunes
            stats = attrs.get("last_analysis_stats", {})
            reputation = attrs.get("reputation", "N/A")
            tags = ", ".join(attrs.get("tags", []))
            
            # Construcción del reporte
            report = [
                f"--- Reporte de VirusTotal: {resource_type} ---",
                f"Reputación: {reputation}",
                f"Estadísticas de Análisis: {VirusTotalHelper.format_stats(stats)}",
                f"Etiquetas: {tags if tags else 'Ninguna'}"
            ]

            # Campos específicos por tipo
            if "names" in attrs:
                report.append(f"Nombres conocidos: {', '.join(attrs['names'][:5])}")
            if "meaningful_name" in attrs:
                report.append(f"Nombre significativo: {attrs['meaningful_name']}")
            if "last_analysis_date" in attrs:
                report.append(f"Fecha último análisis: {attrs['last_analysis_date']}")
            
            # Enlaces al GUI de VirusTotal
            res_id = data.get("data", {}).get("id")
            if res_id:
                if resource_type == "File":
                    report.append(f"Enlace: https://www.virustotal.com/gui/file/{res_id}")
                elif resource_type == "URL":
                    report.append(f"Enlace: https://www.virustotal.com/gui/url/{res_id}")
                elif resource_type == "Domain":
                    report.append(f"Enlace: https://www.virustotal.com/gui/domain/{res_id}")
                elif resource_type == "IP":
                    report.append(f"Enlace: https://www.virustotal.com/gui/ip-address/{res_id}")

            return "\n".join(report)

        except Exception as e:
            return f"Error al formatear la respuesta: {str(e)}"

    @staticmethod
    def url_to_base64_id(url: str) -> str:
        """Genera el identificador Base64 requerido por VT para URLs."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

async def make_request(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Union[Dict[str, Any], str]:
    """Realiza la petición HTTP asíncrona y maneja errores básicos."""
    url = f"{BASE_URL}{endpoint}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=VirusTotalHelper.get_headers(), params=params, timeout=10.0)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return "Error 404: El recurso solicitado no fue encontrado en la base de datos de VirusTotal."
            elif response.status_code == 401:
                return "Error 401: API Key inválida o no autorizada."
            elif response.status_code == 429:
                return "Error 429: Se ha excedido el límite de cuota de la API."
            else:
                return f"Error {response.status_code}: {response.text}"
        except httpx.RequestError as e:
            return f"Error de conexión: {str(e)}"

# --- Definición de Herramientas MCP ---

@mcp.tool()
async def get_file_report(file_hash: str) -> str:
    """
    Consulta el reporte de análisis de un archivo utilizando su hash (MD5, SHA-1 o SHA-256).
    
    Args:
        file_hash: El hash del archivo a consultar.
        
    Returns:
        Un resumen legible de la reputación y análisis del archivo.
    """
    data = await make_request(f"/files/{file_hash}")
    if isinstance(data, str): return data # Retorna mensaje de error si ocurrió
    return VirusTotalHelper.format_response(data, "File")

@mcp.tool()
async def get_ip_report(ip: str) -> str:
    """
    Consulta la reputación y los datos de análisis de una dirección IP.
    
    Args:
        ip: La dirección IP a consultar (ej. 8.8.8.8).
        
    Returns:
        Un resumen legible de la reputación de la IP.
    """
    data = await make_request(f"/ip_addresses/{ip}")
    if isinstance(data, str): return data
    return VirusTotalHelper.format_response(data, "IP")

@mcp.tool()
async def get_domain_report(domain: str) -> str:
    """
    Consulta la reputación y los datos de análisis de un dominio de internet.
    
    Args:
        domain: El nombre de dominio a consultar (ej. google.com).
        
    Returns:
        Un resumen legible de la reputación del dominio.
    """
    data = await make_request(f"/domains/{domain}")
    if isinstance(data, str): return data
    return VirusTotalHelper.format_response(data, "Domain")

@mcp.tool()
async def get_url_report(url: str) -> str:
    """
    Consulta el reporte de análisis de una URL específica.
    Nota: La URL será codificada internamente para cumplir con los requisitos de la API.
    
    Args:
        url: La URL completa a analizar (ej. http://ejemplo.com/login).
        
    Returns:
        Un resumen legible de la reputación de la URL.
    """
    url_id = VirusTotalHelper.url_to_base64_id(url)
    data = await make_request(f"/urls/{url_id}")
    if isinstance(data, str): return data
    return VirusTotalHelper.format_response(data, "URL")

@mcp.tool()
async def search_virustotal(query: str) -> str:
    """
    Realiza una búsqueda general en la base de datos de VirusTotal.
    Útil para buscar combinaciones o cuando no se sabe el tipo exacto de recurso.
    
    Args:
        query: La cadena de búsqueda (puede ser un hash, dominio, IP, etc.).
        
    Returns:
        Un resumen de los resultados encontrados (limitado a los primeros 3 resultados).
    """
    data = await make_request("/search", params={"query": query})
    if isinstance(data, str): return data
    
    # Lógica específica para formatear resultados de búsqueda (lista)
    results = data.get("data", [])
    if not results:
        return "No se encontraron resultados para la búsqueda."
    
    output = [f"--- Resultados de búsqueda para: '{query}' ---"]
    
    # Limitamos a 3 resultados para no saturar el contexto
    for item in results[:3]:
        res_type = item.get("type")
        res_id = item.get("id")
        attrs = item.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        summary = (
            f"\nTipo: {res_type}\n"
            f"ID: {res_id}\n"
            f"Estadísticas: {VirusTotalHelper.format_stats(stats)}"
        )
        output.append(summary)
        
    if len(results) > 3:
        output.append(f"\n... y {len(results) - 3} resultados más.")
        
    return "\n".join(output)

if __name__ == "__main__":
    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
