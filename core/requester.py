import requests
from typing import Dict, Optional
import time

class APIRequester:
    """
    Clase responsable de hacer todas las peticiones HTTP al API objetivo.
    Maneja headers, autenticación, timeouts y retry logic.
    """
    
    def __init__(self, base_url: str, timeout: int = 10, delay: float = 0.5):
        """
        Args:
            base_url: URL base del API (ej: https://api.ejemplo.com)
            timeout: Tiempo máximo de espera por petición (segundos)
            delay: Pausa entre peticiones para evitar rate limiting
        """
        self.base_url = base_url.rstrip('/')  # Eliminar "/" final si existe
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()  # Reutiliza conexiones TCP
    
    def request(self, method: str, endpoint: str, headers: Optional[Dict] = None, 
                data: Optional[Dict] = None, params: Optional[Dict] = None) -> requests.Response:
        """
        Método genérico para hacer peticiones HTTP.
        
        Args:
            method: GET, POST, PUT, DELETE, etc.
            endpoint: Ruta del endpoint (ej: /api/users/123)
            headers: Headers HTTP personalizados (Authorization, Content-Type, etc.)
            data: Body de la petición (para POST/PUT)
            params: Query parameters (?id=123&role=admin)
        
        Returns:
            Objeto Response de requests
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            # Hacer la petición
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers or {},
                json=data,
                params=params,
                timeout=self.timeout,
                verify=True  # Verificar certificados SSL (cambiar a False solo en labs)
            )
            
            # Pausa para no saturar el servidor
            time.sleep(self.delay)
            
            return response
            
        except requests.exceptions.Timeout:
            print(f"Timeout en {url}")
            raise
        except requests.exceptions.ConnectionError:
            print(f"Error de conexión a {url}")
            raise
        except Exception as e:
            print(f"Error inesperado: {str(e)}")
            raise
    
    def get(self, endpoint: str, headers: Optional[Dict] = None, params: Optional[Dict] = None):
        """Atajo para peticiones GET"""
        return self.request('GET', endpoint, headers=headers, params=params)
    
    def post(self, endpoint: str, headers: Optional[Dict] = None, data: Optional[Dict] = None):
        """Atajo para peticiones POST"""
        return self.request('POST', endpoint, headers=headers, data=data)
    
    def put(self, endpoint: str, headers: Optional[Dict] = None, data: Optional[Dict] = None):
        """Atajo para peticiones PUT"""
        return self.request('PUT', endpoint, headers=headers, data=data)
    
    def delete(self, endpoint: str, headers: Optional[Dict] = None):
        """Atajo para peticiones DELETE"""
        return self.request('DELETE', endpoint, headers=headers)
