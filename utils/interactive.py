"""
API Fuzzer - Módulo de Configuración

Módulo de configuración interactiva para el API Fuzzer.
Permite agregar targets manualmente sin editar archivos YAML.

Autor: Elisa Elias (AEGIS / H4ck The World)
"""

import yaml
import json
from typing import Dict, List, Optional
from pathlib import Path
import re
import base64 # Importación necesaria para Basic Auth

# ASCII Art de Cinnamoroll para el banner
CINNAGENERATED_BANNER = """
⠀⠀⡠⠂⠉⠉⠐⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀
⠀⠸⠀⠀⠀⠀⠀⠘⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠃⠀⠀⠀⢄⠀⠀
⠀⠇⠀⠀⠀⠀⠀⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⠈⡆⠀
⢀⡃⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⢰⠄
⠈⢡⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠸⠄
⠀⠀⠡⡀⠀⠀⠀⠀⠀⠀⠑⠦⡤⠖⠊⠉⠀⠀⠀⠀⠀⠉⠑⠢⣄⣀⡠⠴⠃⠀⠀⠀⠀⠀⢀⠇⠀
⠀⠀⠀⠁⢀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠋⠁⠀⠀⠀⠀⠀⠀⢀⡘⠀⠀
⠀⠀⠀⠀⠀⠁⠢⠄⣀⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠢⡀⠀⠀⠀⢀⠀⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠰⠁⠀⢠⢶⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⢦⠀⠀⠙⡒⠒⠉⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢇⠀⠀⠈⠉⠁⠀⠀⠰⠤⠤⠤⡴⠀⠀⠀⠈⠙⠀⠀⡀⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⣼⠋⢳⠀⠀⠀⠀⠈⠒⠀⠀⠀⠀⢠⠊⠙⣤⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠑⠒⠒⠒⠒⠒⠒⠒⠒⠒⠋⡀⠐⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

class InteractiveConfigurator:
    """
    Configurador interactivo para agregar targets manualmente.
    """
    
    def __init__(self):
        self.target = {}
    
    def start(self) -> Dict:
        """
        Inicia el asistente interactivo para configurar un target.
        
        Returns:
            Diccionario con la configuración del target
        """
        print(CINNAGENERATED_BANNER)
        print("="*70)
        print("CONFIGURADOR INTERACTIVO DE TARGET")
        print("Autor: Elisa Elias")
        print("="*70)
        print("\nVamos a configurar un nuevo target paso a paso.\n")
        
        # 1. Información básica
        self.target['name'] = self._get_input(
            "Nombre del target",
            default="Custom API",
            validator=lambda x: len(x) > 0
        )
        
        self.target['base_url'] = self._get_input(
            "URL base del API (ej: https://api.example.com)",
            validator=self._validate_url
        )
        
        self.target['enabled'] = True
        
        # 2. Configurar usuarios
        print("\n" + "-"*70)
        print("CONFIGURACIÓN DE USUARIOS")
        print("-"*70)
        self.target['users'] = self._configure_users()
        
        # 3. Configurar endpoints
        print("\n" + "-"*70)
        print("CONFIGURACIÓN DE ENDPOINTS")
        print("-"*70)
        self.target['endpoints'] = self._configure_endpoints()
        
        # 4. Resumen y confirmación
        self._show_summary()
        
        return {'targets': [self.target]}
    
    def _get_input(self, prompt: str, default: Optional[str] = None, 
                   validator=None) -> str:
        """
        Solicita input del usuario con validación opcional.
        """
        while True:
            if default:
                user_input = input(f"{prompt} [{default}]: ").strip()
                if not user_input:
                    user_input = default
            else:
                user_input = input(f"{prompt}: ").strip()
            
            # Validar
            if validator:
                if validator(user_input):
                    return user_input
                else:
                    print("    Valor inválido, intenta de nuevo")
            else:
                if user_input:
                    return user_input
                print("    Este campo es obligatorio")
    
    def _get_yes_no(self, prompt: str, default: bool = True) -> bool:
        """Obtiene una respuesta sí/no del usuario."""
        default_str = "S/n" if default else "s/N"
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        
        if not response:
            return default
        
        return response in ['s', 'si', 'sí', 'y', 'yes']
    
    def _validate_url(self, url: str) -> bool:
        """Valida que sea una URL válida."""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))
    
    def _configure_users(self) -> List[Dict]:
        """Configuración interactiva de usuarios."""
        users = []
        
        print("\nNecesitas configurar al menos 1 usuario para pruebas.")
        print("Recomendado: 2-3 usuarios con diferentes roles\n")
        
        user_count = 1
        while True:
            print(f"\n--- Usuario {user_count} ---")
            
            user = {}
            user['name'] = self._get_input(
                f"Nombre del usuario {user_count}",
                default=f"user{user_count}"
            )
            
            user['id'] = self._get_input(
                "ID del usuario (ej: 123, user-abc, etc.)",
                default=str(100 + user_count)
            )
            
            user['role'] = self._get_input(
                "Rol del usuario (ej: user, admin, guest)",
                default="user"
            )
            
            # Token de autenticación
            print("\nTipos de autenticación:")
            print("    1. Bearer Token (JWT)")
            print("    2. API Key")
            print("    3. Basic Auth")
            print("    4. Sin autenticación (para tests)")
            
            auth_type = self._get_input(
                "Tipo de autenticación [1-4]",
                default="1",
                validator=lambda x: x in ['1', '2', '3', '4']
            )
            
            if auth_type == '1':
                token = self._get_input("Bearer Token (sin 'Bearer ' prefix)")
                user['token'] = f"Bearer {token}"
            elif auth_type == '2':
                api_key = self._get_input("API Key")
                user['token'] = f"ApiKey {api_key}"
            elif auth_type == '3':
                username = self._get_input("Username")
                password = self._get_input("Password")
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                user['token'] = f"Basic {credentials}"
            else:
                user['token'] = ""
            
            users.append(user)
            user_count += 1
            
            # ¿Agregar otro usuario?
            if not self._get_yes_no("\n¿Agregar otro usuario?", default=False):
                break
            
            if len(users) >= 5:
                print("\nMáximo 5 usuarios alcanzado")
                break
        
        return users
    
    def _configure_endpoints(self) -> List[Dict]:
        """Configuración interactiva de endpoints."""
        endpoints = []
        
        print("\nAhora vamos a configurar los endpoints a testear.")
        print("Puedes agregar endpoints específicos o usar auto-discovery.\n")
        
        # Opción de auto-discovery
        if self._get_yes_no("¿Quieres que intente descubrir endpoints automáticamente?", default=False):
            print("\nAuto-discovery intentará encontrar endpoints comunes")
            print("Esto puede tomar unos segundos...\n")
            
            discovered = self._auto_discover_endpoints()
            if discovered:
                print(f"\nSe descubrieron {len(discovered)} endpoints")
                if self._get_yes_no("¿Quieres usar estos endpoints?", default=True):
                    endpoints.extend(discovered)
        
        # Configuración manual
        print("\n--- Configuración manual de endpoints ---\n")
        
        endpoint_count = len(endpoints) + 1
        while True:
            print(f"\n--- Endpoint {endpoint_count} ---")
            
            endpoint = {}
            
            path = self._get_input(
                "Path del endpoint (ej: /api/v1/users/{id})"
            )
            endpoint['path'] = path
            
            # Detectar si tiene parámetros
            has_id = '{id}' in path or '{uuid}' in path
            
            # Métodos HTTP
            print("\nMétodos HTTP disponibles:")
            print("    1. GET")
            print("    2. POST")
            print("    3. PUT")
            print("    4. DELETE")
            print("    5. Múltiples (separados por coma)")
            
            method_choice = self._get_input(
                "Selecciona método(s) [1-5]",
                default="1"
            )
            
            if method_choice == '5':
                methods_str = self._get_input(
                    "Métodos separados por coma (ej: GET,POST,PUT)",
                    default="GET"
                )
                endpoint['methods'] = [m.strip().upper() for m in methods_str.split(',')]
            else:
                method_map = {'1': 'GET', '2': 'POST', '3': 'PUT', '4': 'DELETE'}
                endpoint['methods'] = [method_map.get(method_choice, 'GET')]
            
            # Autenticación requerida
            endpoint['auth_required'] = self._get_yes_no(
                "¿Requiere autenticación?",
                default=True
            )
            
            # Módulos a ejecutar
            print("\nMódulos disponibles:")
            print("    1. BOLA Detector (recomendado si tiene {id})")
            print("    2. Auth Detector")
            print("    3. Data Exposure Detector")
            print("    4. Todos los módulos")
            
            modules_choice = self._get_input(
                "¿Qué módulos ejecutar? [1-4]",
                default="4" if has_id else "2"
            )
            
            if modules_choice == '1':
                endpoint['test_modules'] = ['bola_detector']
            elif modules_choice == '2':
                endpoint['test_modules'] = ['auth_detector']
            elif modules_choice == '3':
                endpoint['test_modules'] = ['data_exposure_detector']
            else:
                endpoint['test_modules'] = [
                    'bola_detector', 
                    'auth_detector', 
                    'data_exposure_detector'
                ]
            
            endpoints.append(endpoint)
            endpoint_count += 1
            
            # ¿Agregar otro endpoint?
            if not self._get_yes_no("\n¿Agregar otro endpoint?", default=True):
                break
            
            if len(endpoints) >= 20:
                print("\nMáximo 20 endpoints alcanzado")
                break
        
        return endpoints
    
    def _auto_discover_endpoints(self) -> List[Dict]:
        """
        Intenta descubrir endpoints comunes automáticamente.
        """
        from core.requester import APIRequester
        
        discovered = []
        common_paths = [
            '/api/v1/users',
            '/api/v1/users/{id}',
            '/api/users',
            '/api/users/{id}',
            '/api/v1/auth/login',
            '/api/v1/auth/register',
            '/api/auth/login',
            '/api/login',
            '/api/v1/orders',
            '/api/v1/orders/{id}',
            '/api/v1/products',
            '/api/v1/products/{id}',
            '/health',
            '/healthcheck',
            '/api/health',
        ]
        
        # Necesitamos una URL base válida para el requester
        base_url = self.target.get('base_url', 'http://localhost')
        requester = APIRequester(base_url=base_url, timeout=5, delay=0.1)
        
        for path in common_paths:
            try:
                response = requester.get(path)
                
                # Si responde (cualquier código < 500), agregar
                if response.status_code < 500:
                    print(f"    Encontrado: {path} (HTTP {response.status_code})")
                    
                    endpoint = {
                        'path': path,
                        'methods': ['GET'],
                        'auth_required': response.status_code in [401, 403],
                        'test_modules': self._suggest_modules(path)
                    }
                    discovered.append(endpoint)
                
            except Exception:
                # Endpoint no accesible, continuar
                pass
        
        return discovered
    
    def _suggest_modules(self, path: str) -> List[str]:
        """Sugiere módulos basándose en el path del endpoint."""
        modules = []
        
        # Si tiene {id}, sugerir BOLA
        if '{id}' in path or '{uuid}' in path:
            modules.append('bola_detector')
        
        # Si es de auth, sugerir Auth detector
        if 'auth' in path.lower() or 'login' in path.lower():
            modules.append('auth_detector')
        
        # Siempre agregar Data Exposure
        modules.append('data_exposure_detector')
        
        return modules if modules else ['bola_detector', 'auth_detector', 'data_exposure_detector']
    
    def _show_summary(self):
        """Muestra un resumen de la configuración."""
        print("\n" + "="*70)
        print("RESUMEN DE CONFIGURACIÓN")
        print("="*70)
        print(f"\nTarget: {self.target['name']}")
        print(f"URL: {self.target['base_url']}")
        print(f"Usuarios: {len(self.target['users'])}")
        
        for user in self.target['users']:
            print(f"    - {user['name']} (ID: {user['id']}, Rol: {user['role']})")
        
        print(f"\nEndpoints: {len(self.target['endpoints'])}")
        for endpoint in self.target['endpoints']:
            print(f"    - {endpoint['path']} [{', '.join(endpoint['methods'])}]")
        
        print("\n" + "="*70)
    
    def save_to_file(self, filename: str = "custom_target.yaml"):
        """
        Guarda la configuración a un archivo YAML.
        """
        filepath = Path(filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump({'targets': [self.target]}, f, 
                      default_flow_style=False, allow_unicode=True)
        
        print(f"\nConfiguración guardada en: {filepath}")
        return filepath


class QuickScanConfigurator:
    """
    Configurador rápido para scans con parámetros mínimos.
    """
    
    @staticmethod
    def create_target(url: str, token: str = None, user_id: str = "1") -> Dict:
        """
        Crea un target rápido con configuración mínima.
        
        Args:
            url: URL base del API
            token: Token de autenticación (opcional)
            user_id: ID del usuario (default: "1")
        
        Returns:
            Configuración del target
        """
        target = {
            'name': f'Quick Scan - {url}',
            'base_url': url,
            'enabled': True,
            'users': [],
            'endpoints': []
        }
        
        # Usuario básico
        user = {
            'name': 'quickscan_user',
            'id': user_id,
            'role': 'user',
            'token': f'Bearer {token}' if token else ''
        }
        target['users'].append(user)
        
        # Endpoints comunes con auto-discovery
        common_endpoints = [
            {
                'path': '/api/v1/users/{id}',
                'methods': ['GET'],
                'auth_required': True,
                'test_modules': ['bola_detector', 'data_exposure_detector']
            },
            {
                'path': '/api/v1/users',
                'methods': ['GET'],
                'auth_required': True,
                'test_modules': ['data_exposure_detector']
            },
            {
                'path': '/api/v1/auth/login',
                'methods': ['POST'],
                'auth_required': False,
                'test_modules': ['auth_detector']
            }
        ]
        
        target['endpoints'] = common_endpoints
        
        return {'targets': [target]}
