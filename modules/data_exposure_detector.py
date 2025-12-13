import re
import json
from typing import Dict, List, Any, Set
from modules.base_detector import BaseDetector
from core.requester import APIRequester

class DataExposureDetector(BaseDetector):
    """
    Detector de Excessive Data Exposure.
    
    Detecta:
    - Campos sensibles en respuestas (passwords, tokens, keys)
    - PII expuesta (SSN, teléfonos, emails, direcciones)
    - Información técnica del sistema
    - Diferencias en respuestas según rol de usuario
    - Stack traces y mensajes de error verbosos
    """
    
    def __init__(self, requester: APIRequester):
        super().__init__(requester, "Excessive Data Exposure Detector")
        
        # Patrones de datos sensibles
        self.sensitive_patterns = {
            # Credenciales
            'password_hash': r'(password_hash|passwd_hash|pwd_hash|hashed_password)',
            'password_plain': r'"password"\s*:\s*"[^"]{6,}"',
            'api_key': r'(api_key|apikey|api-key|key)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}',
            'secret_key': r'(secret|secret_key|secretkey)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}',
            'access_token': r'(access_token|accesstoken|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]{20,}',
            'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'jwt_token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            
            # PII (Personally Identifiable Information)
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'phone': r'(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            
            # Información técnica/interna
            'stack_trace': r'(Traceback|Exception|Error).*?at\s+[\w\.]+\(',
            'file_path': r'([A-Z]:\\|/)([\w-]+/)+[\w\.-]+',
            'database_connection': r'(mongodb|mysql|postgresql|redis)://[^\s]+',
            'internal_ip': r'\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
        }
        
        # Campos sensibles comunes en JSON
        self.sensitive_fields = {
            'password', 'passwd', 'pwd', 'password_hash', 'hashed_password',
            'api_key', 'apikey', 'secret', 'secret_key', 'private_key',
            'access_token', 'refresh_token', 'token', 'auth_token',
            'ssn', 'social_security', 'tax_id', 'credit_card', 'cvv',
            'salary', 'compensation', 'bank_account', 'routing_number',
            'internal_notes', 'admin_notes', 'debug_info', 'stack_trace'
        }
    
    def run(self, target: Dict, endpoint: Dict) -> List[Dict]:
        """
        Ejecuta las pruebas de data exposure sobre el endpoint.
        
        Args:
            target: Configuración del target
            endpoint: Configuración del endpoint a testear
        
        Returns:
            Lista de hallazgos
        """
        findings = []
        endpoint_path = endpoint.get('path')
        methods = endpoint.get('methods', ['GET'])
        
        print(f"       Analizando exposición de datos en: {endpoint_path}")
        
        users = target.get('users', [])
        
        if not users:
            print(f"             No hay usuarios configurados, análisis limitado")
            return findings
        
        # Test 1: Análisis de campos sensibles en respuestas
        for user in users:
            finding = self._analyze_response_data(
                endpoint_path,
                methods[0],
                {'Authorization': user['token']},
                user['name']
            )
            if finding['vulnerable']:
                findings.append(finding)
        
        # Test 2: Comparación de respuestas entre diferentes roles
        if len(users) >= 2:
            finding = self._compare_role_responses(endpoint_path, users)
            if finding['vulnerable']:
                findings.append(finding)
        
        # Test 3: Análisis de mensajes de error
        finding = self._test_error_messages(endpoint_path)
        if finding['vulnerable']:
            findings.append(finding)
        
        return findings
    
    def _analyze_response_data(self, endpoint: str, method: str, 
                              headers: Dict, user_name: str) -> Dict[str, Any]:
        """
        Test 1: Analiza la respuesta en busca de datos sensibles.
        """
        print(f"             Test: Análisis de datos sensibles (usuario: {user_name})")
        
        finding = {
            'type': 'SENSITIVE_DATA_EXPOSURE',
            'endpoint': endpoint,
            'user': user_name,
            'vulnerable': False,
            'severity': 'INFO',
            'sensitive_data_found': []
        }
        
        try:
            response = self.requester.request(method, endpoint, headers=headers)
            
            if response.status_code != 200:
                print(f"                 Respuesta: HTTP {response.status_code}")
                return finding
            
            response_text = response.text
            
            # Analizar con patrones regex
            patterns_found = self._scan_with_patterns(response_text)
            
            # Analizar campos JSON si es JSON
            fields_found = set()
            try:
                response_json = response.json()
                fields_found = self._scan_json_fields(response_json)
            except json.JSONDecodeError:
                pass
            
            # Combinar hallazgos
            all_findings = patterns_found | fields_found
            
            if all_findings:
                print(f"                 Datos sensibles encontrados: {len(all_findings)}")
                for item in list(all_findings)[:5]:  # Mostrar primeros 5
                    print(f"                    - {item}")
                
                finding['vulnerable'] = True
                finding['sensitive_data_found'] = list(all_findings)
                
                # Clasificar severidad según tipo de datos
                if any(x in all_findings for x in ['password_plain', 'api_key', 'secret_key', 'private_key']):
                    finding['severity'] = 'CRITICAL'
                elif any(x in all_findings for x in ['ssn', 'credit_card', 'password_hash']):
                    finding['severity'] = 'HIGH'
                elif any(x in all_findings for x in ['email', 'phone', 'ip_address', 'stack_trace']):
                    finding['severity'] = 'MEDIUM'
                else:
                    finding['severity'] = 'LOW'
                
                finding['evidence'] = {
                    'total_sensitive_fields': len(all_findings),
                    'fields': list(all_findings),
                    'response_size': len(response_text),
                    'description': f'Se encontraron {len(all_findings)} campos/patrones sensibles en la respuesta'
                }
            else:
                print(f"                 No se detectaron datos sensibles obvios")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def _scan_with_patterns(self, text: str) -> Set[str]:
        """
        Escanea el texto con patrones regex para detectar datos sensibles.
        
        Returns:
            Set de tipos de datos sensibles encontrados
        """
        found = set()
        
        for data_type, pattern in self.sensitive_patterns.items():
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                found.add(data_type)
        
        return found
    
    def _scan_json_fields(self, data: Any, parent_key: str = '') -> Set[str]:
        """
        Escanea recursivamente un objeto JSON en busca de campos sensibles.
        
        Args:
            data: Objeto JSON (dict, list, o primitivo)
            parent_key: Clave padre para contexto
        
        Returns:
            Set de campos sensibles encontrados
        """
        found = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                # Verificar si el nombre del campo es sensible
                key_lower = key.lower()
                if key_lower in self.sensitive_fields:
                    found.add(key)
                
                # Verificar si contiene palabras sensibles
                for sensitive in self.sensitive_fields:
                    if sensitive in key_lower:
                        found.add(key)
                        break
                
                # Recursión en valores
                found.update(self._scan_json_fields(value, key))
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                fields_in_item = self._scan_json_fields(item, parent_key)
                # Renombrar campos anidados en listas para el reporte (ej: data[0].name)
                renamed_fields = {f"{parent_key}.{field}" for field in fields_in_item if not field.startswith(parent_key)}
                found.update(renamed_fields if renamed_fields else fields_in_item)

        return found
    
    def _compare_role_responses(self, endpoint: str, users: List[Dict]) -> Dict[str, Any]:
        """
        Test 2: Compara respuestas entre diferentes roles de usuario.
        
        Detecta si usuarios con diferentes roles reciben diferentes cantidades
        de información (role-based data exposure).
        """
        print(f"             Test: Comparación de respuestas por rol")
        
        finding = {
            'type': 'ROLE_BASED_DATA_EXPOSURE',
            'endpoint': endpoint,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        try:
            responses_by_role = {}
            
            # Obtener respuestas de cada usuario
            for user in users:
                response = self.requester.get(
                    endpoint,
                    headers={'Authorization': user['token']}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        role = user.get('role', 'unknown')
                        
                        # Guardar información sobre la respuesta
                        responses_by_role[role] = {
                            'user': user['name'],
                            'fields': self._get_all_fields(data),
                            'field_count': len(self._get_all_fields(data)),
                            'response_size': len(response.text)
                        }
                    except json.JSONDecodeError:
                        pass
            
            if len(responses_by_role) < 2:
                print(f"                 No hay suficientes respuestas para comparar")
                return finding
            
            # Comparar respuestas
            roles = list(responses_by_role.keys())
            role1, role2 = roles[0], roles[1]
            
            fields1 = responses_by_role[role1]['fields']
            fields2 = responses_by_role[role2]['fields']
            
            # Campos que solo ve un rol
            exclusive_to_role1 = fields1 - fields2
            exclusive_to_role2 = fields2 - fields1
            
            print(f"                 {role1}: {len(fields1)} campos")
            print(f"                 {role2}: {len(fields2)} campos")
            
            if exclusive_to_role1 or exclusive_to_role2:
                print(f"                 Diferencias detectadas en exposición de datos")
                
                if exclusive_to_role1:
                    print(f"                    Solo para {role1}: {list(exclusive_to_role1)[:3]}")
                if exclusive_to_role2:
                    print(f"                    Solo para {role2}: {list(exclusive_to_role2)[:3]}")
                
                finding['vulnerable'] = True
                finding['severity'] = 'MEDIUM'
                finding['evidence'] = {
                    'role1': role1,
                    'role2': role2,
                    'role1_exclusive_fields': list(exclusive_to_role1),
                    'role2_exclusive_fields': list(exclusive_to_role2),
                    'description': f'Diferentes roles reciben diferentes campos de datos'
                }
                
                # Si los campos exclusivos son sensibles, aumentar severidad
                sensitive_exposed = (exclusive_to_role1 | exclusive_to_role2) & self.sensitive_fields
                if sensitive_exposed:
                    finding['severity'] = 'HIGH'
                    finding['evidence']['sensitive_fields_exposed'] = list(sensitive_exposed)
            else:
                print(f"                 Respuestas consistentes entre roles")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def _get_all_fields(self, data: Any, prefix: str = '') -> Set[str]:
        """
        Obtiene recursivamente todos los nombres de campos en un objeto JSON.
        
        Returns:
            Set con todos los nombres de campos (incluye nested)
        """
        fields = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                fields.add(full_key)
                fields.update(self._get_all_fields(value, full_key))
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                # Usar el prefijo del padre de la lista para todos los elementos
                list_prefix = prefix or 'root'
                # La recursión no necesita el índice en el prefijo para la comparación de campos
                fields.update(self._get_all_fields(item, list_prefix)) 
        
        return fields
    
    def _test_error_messages(self, endpoint: str) -> Dict[str, Any]:
        """
        Test 3: Analiza mensajes de error en busca de información sensible.
        
        Los errores verbosos pueden revelar:
        - Stack traces completos
        - Paths del filesystem
        - Versiones de software
        - Estructura de base de datos
        """
        print(f"             Test: Análisis de mensajes de error")
        
        finding = {
            'type': 'VERBOSE_ERROR_MESSAGES',
            'endpoint': endpoint,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        # Payloads que causan errores
        error_payloads = [
            {'invalid_param': 'x' * 1000},  # String muy largo
            {'id': -1},                     # ID negativo
            {'id': 'invalid'},              # Tipo incorrecto
            {'date': '9999-99-99'},         # Fecha inválida
        ]
        
        try:
            verbose_errors = []
            
            for payload in error_payloads:
                response = self.requester.get(endpoint, params=payload)
                
                # Buscar en respuestas de error (4xx, 5xx)
                if 400 <= response.status_code < 600:
                    error_text = response.text
                    
                    # Detectar información sensible en el error
                    if any([
                        re.search(r'Traceback|Exception|Error.*at\s+', error_text),
                        re.search(r'[A-Z]:\\[\w\\]+|/[\w/]+\.py', error_text),
                        re.search(r'line \d+', error_text),
                        re.search(r'SQL|Query|SELECT|INSERT', error_text, re.IGNORECASE),
                        len(error_text) > 500,  # Mensaje muy largo
                    ]):
                        verbose_errors.append({
                            'status': response.status_code,
                            'payload': payload,
                            'error_length': len(error_text),
                            'sample': error_text[:200]
                        })
            
            if verbose_errors:
                print(f"                 Mensajes de error verbosos detectados")
                print(f"                 {len(verbose_errors)} error(es) con información sensible")
                
                finding['vulnerable'] = True
                finding['severity'] = 'LOW'
                finding['evidence'] = {
                    'verbose_errors_count': len(verbose_errors),
                    'examples': verbose_errors[:2],  # Primeros 2 ejemplos
                    'description': 'Los mensajes de error exponen información técnica interna'
                }
            else:
                print(f"                 Mensajes de error genéricos")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def generate_report(self) -> str:
        """Genera reporte de hallazgos de data exposure"""
        if not self.findings:
            return f"\n{'='*60}\n  {self.name}: Sin vulnerabilidades\n{'='*60}\n"
        
        report = f"\n{'='*60}\n"
        report += f"{self.name.upper()}\n"
        report += f"{'='*60}\n"
        report += f"Vulnerabilidades encontradas: {len(self.findings)}\n\n"
        
        for idx, finding in enumerate(self.findings, 1):
            report += f"[{idx}] {finding['type']}\n"
            report += f"    Endpoint: {finding['endpoint']}\n"
            report += f"    Severidad: {finding['severity']}\n"
            
            if finding['type'] == 'SENSITIVE_DATA_EXPOSURE':
                sensitive = finding.get('sensitive_data_found', [])
                report += f"    Datos sensibles: {', '.join(sensitive[:5])}\n"
                if len(sensitive) > 5:
                    report += f"    ... y {len(sensitive) - 5} más\n"
            
            if 'evidence' in finding:
                report += f"    {finding['evidence'].get('description', '')}\n"
            
            report += "\n"
        
        return report
