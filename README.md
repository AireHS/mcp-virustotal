# VirusTotal MCP Server

Este es un servidor MCP (Model Context Protocol) implementado en Python utilizando `fastmcp`. Permite a asistentes de IA (como Claude Desktop) interactuar directamente con la API v3 de VirusTotal para realizar análisis de seguridad sobre archivos, IPs, dominios y URLs.

## 🚀 Características

*   **Análisis de Archivos**: Consulta reportes mediante hash (MD5, SHA-1, SHA-256).
*   **Reputación de IP**: Obtiene información sobre direcciones IP sospechosas.
*   **Reportes de Dominios**: Verifica la reputación de dominios.
*   **Escaneo de URLs**: Consulta análisis de URLs específicas.
*   **Búsqueda General**: Busca cualquier artefacto en la base de datos de VirusTotal.
*   **Salida Formateada**: Las respuestas están procesadas para ser legibles por humanos y LLMs, evitando JSONs crudos innecesarios.

## 📋 Prerrequisitos

*   Python 3.10 o superior.
*   Una cuenta en VirusTotal y una **API Key** (gratuita o premium).

## 🛠️ Instalación

1.  **Clona o descarga este repositorio** en tu máquina local.

2.  **Crea un entorno virtual** (recomendado):
    ```bash
    python -m venv venv
    ```

3.  **Activa el entorno virtual**:
    *   Windows: `venv\Scripts\activate`
    *   macOS/Linux: `source venv/bin/activate`

4.  **Instala las dependencias**:
    ```bash
    pip install -r requirements.txt
    ```

## ⚙️ Configuración

El servidor necesita tu API Key de VirusTotal para funcionar.

1.  Crea un archivo llamado `.env` en la raíz del proyecto.
2.  Agrega tu clave de la siguiente manera:

```env
VIRUSTOTAL_API_KEY=tu_clave_api_aqui_sin_comillas
```

## 🤖 Integración con Claude Desktop

Para usar este servidor con la aplicación de escritorio de Claude, edita tu archivo de configuración (generalmente en `%APPDATA%\Claude\claude_desktop_config.json` en Windows).

Asegúrate de usar las rutas absolutas a tu entorno virtual y al archivo `server.py`.

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "python",
      "args": ["C:\\Ruta\\A\\Tu\\Proyecto\\server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "tu_clave_api_aqui"
      }
    }
  }
}
```

> **Nota**: Si ya tienes el archivo `.env` configurado, la sección `"env"` en el JSON es opcional, pero es una buena práctica para asegurar que la variable se pase correctamente.

## 🧰 Herramientas Disponibles

| Herramienta | Descripción | Ejemplo de uso |
| :--- | :--- | :--- |
| `get_file_report` | Obtiene el reporte de un archivo por su hash. | `get_file_report(file_hash="...")` |
| `get_ip_report` | Consulta la reputación de una IP. | `get_ip_report(ip="8.8.8.8")` |
| `get_domain_report` | Consulta la reputación de un dominio. | `get_domain_report(domain="google.com")` |
| `get_url_report` | Consulta el análisis de una URL. | `get_url_report(url="http://ejemplo.com")` |
| `search_virustotal` | Búsqueda general (hash, url, ip, etc). | `search_virustotal(query="malware")` |

## 📄 Licencia

Este proyecto está diseñado para fines educativos y de desarrollo.