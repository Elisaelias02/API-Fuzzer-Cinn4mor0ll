import jwt
import base64
import json
import hashlib
from typing import Dict, List, Any, Optional
from modules.base_detector import BaseDetector
from core.requester import APIRequester
import requests
import time

class AuthDetector(BaseDetector):
    """
    Detector de vulnerabilidades de Broken Authentication.
    
    Detecta:
    - JWT con algoritmo 'none'
    - JWT con secretos débiles
    - JWT sin validación de firma
    - Endpoints sin autenticación requerida
    - Tokens predecibles
    - Falta de rate limiting
    """
    
    def __init__(self, requester: APIRequester):
        super().__init__(requester, "Broken Authentication Detector")
        
        # Diccionario de secretos comunes para JWT brute force
        self.common_secrets = [
            'secret', 'password', '123456', 'admin', 'qwerty',
            'your-256-bit-secret', 'mysecretkey', 'jwt-secret',
            'secretkey', 'key', 'your_secret_key', 'change_me',
            'default', 'test', 'dev', 'development', 'production'
        ]
    
    def run(self, target: Dict, endpoint: Dict) -> List[Dict]:
        """
        Ejecuta las pruebas de autenticación sobre el endpoint.
        
        Args:
            target: Configuración del target
            endpoint: Configuración del endpoint a testear
        
        Returns:
            Lista de hallazgos
        """
        findings = []
        endpoint_path = endpoint.get('path')
        methods = endpoint.get('methods', ['GET'])
        auth_required = endpoint.get('auth_required', True)
        
        print(f"       Analizando autenticación en: {endpoint_path}")
        
        # Test 1: Verificar si endpoint DEBERÍA tener auth pero no la requiere
        if auth_required:
            finding = self._test_missing_auth(endpoint_path, methods[0])
            if finding['vulnerable']:
                findings.append(finding)
        
        # Test 2: Analizar tokens JWT si hay usuarios configurados
        users = target.get('users', [])
        if users:
            for user in users:
                token = user.get('token', '').replace('Bearer ', '')
                if token:
                    # Test JWT
                    jwt_findings = self._analyze_jwt(token, endpoint_path, user['name'])
                    findings.extend(jwt_findings)
        
        # Test 3: Test de rate limiting en endpoints de login
        if 'login' in endpoint_path.lower() or 'auth' in endpoint_path.lower():
            finding = self._test_rate_limiting(endpoint_path)
            if finding['vulnerable']:
                findings.append(finding)
        
        # Test 4: Enumeración de usuarios (si es endpoint de registro/login)
        if 'register' in endpoint_path.lower() or 'login' in endpoint_path.lower():
            finding = self._test_user_enumeration(endpoint_path)
            if finding['vulnerable']:
                findings.append(finding)
        
        return findings
    
    def _test_missing_auth(self, endpoint: str, method: str = 'GET') -> Dict[str, Any]:
        """
        Test 1: Verificar si endpoint responde sin autenticación.
        
        Prueba acceder al endpoint sin headers de autenticación.
        Si responde con 200, es una vulnerabilidad.
        """
        print(f"             Test: Acceso sin autenticación")
        
        finding = {
            'type': 'MISSING_AUTHENTICATION',
            'endpoint': endpoint,
            'method': method,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        try:
            # Intentar acceso sin ningún header de autenticación
            response = self.requester.request(method, endpoint, headers={})
            
            if response.status_code == 200:
                print(f"                 VULNERABLE: Endpoint accesible sin autenticación")
                finding['vulnerable'] = True
                finding['severity'] = 'CRITICAL'
                finding['evidence'] = {
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'description': 'El endpoint responde sin requerir autenticación'
                }
            elif response.status_code in [401, 403]:
                print(f"                 Protegido: HTTP {response.status_code}")
            else:
                print(f"                 Respuesta: HTTP {response.status_code}")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def _analyze_jwt(self, token: str, endpoint: str, user_name: str) -> List[Dict]:
        """
        Test 2: Análisis completo de JWT.
        
        Verifica:
        - Algoritmo 'none'
        - Secreto débil
        - Sin expiración
        - Claims sensibles
        """
        print(f"             Test: Análisis JWT de usuario '{user_name}'")
        findings = []
        
        try:
            # Decodificar sin verificar (para analizar estructura)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            print(f"                 Algoritmo: {header.get('alg', 'N/A')}")
            print(f"                 Usuario en token: {unverified_payload.get('sub', 'N/A')}")
            
            # TEST 2.1: Algoritmo 'none'
            if header.get('alg', '').lower() == 'none':
                print(f"                 CRÍTICO: Algoritmo 'none' detectado")
                findings.append({
                    'type': 'JWT_ALGORITHM_NONE',
                    'endpoint': endpoint,
                    'user': user_name,
                    'vulnerable': True,
                    'severity': 'CRITICAL',
                    'evidence': {
                        'algorithm': header.get('alg'),
                        'description': 'JWT acepta algoritmo "none", permitiendo bypass de firma'
                    }
                })
            
            # TEST 2.2: Secreto débil (brute force)
            print(f"                 Intentando brute force de secreto...")
            weak_secret = self._brute_force_jwt_secret(token)
            if weak_secret:
                print(f"                 CRÍTICO: Secreto débil encontrado: '{weak_secret}'")
                findings.append({
                    'type': 'JWT_WEAK_SECRET',
                    'endpoint': endpoint,
                    'user': user_name,
                    'vulnerable': True,
                    'severity': 'CRITICAL',
                    'evidence': {
                        'secret_found': weak_secret,
                        'description': f'El secreto JWT es débil y fue crackeado: {weak_secret}'
                    }
                })
            else:
                print(f"                 Secreto no encontrado en diccionario común")
            
            # TEST 2.3: Sin expiración (exp claim)
            if 'exp' not in unverified_payload:
                print(f"                 Token sin expiración (claim 'exp' ausente)")
                findings.append({
                    'type': 'JWT_NO_EXPIRATION',
                    'endpoint': endpoint,
                    'user': user_name,
                    'vulnerable': True,
                    'severity': 'MEDIUM',
                    'evidence': {
                        'description': 'JWT no tiene claim de expiración, puede usarse indefinidamente'
                    }
                })
            else:
                exp_time = unverified_payload['exp']
                current_time = time.time()
                if exp_time > current_time + (365 * 24 * 60 * 60):  # Más de 1 año
                    print(f"                 Token con expiración muy larga (>1 año)")
                    findings.append({
                        'type': 'JWT_LONG_EXPIRATION',
                        'endpoint': endpoint,
                        'user': user_name,
                        'vulnerable': True,
                        'severity': 'LOW',
                        'evidence': {
                            'expiration_seconds': exp_time - current_time,
                            'description': 'JWT tiene expiración muy larga'
                        }
                    })
            
            # TEST 2.4: Claims sensibles en payload
            sensitive_claims = self._check_sensitive_claims(unverified_payload)
            if sensitive_claims:
                print(f"                 Claims sensibles: {', '.join(sensitive_claims)}")
                findings.append({
                    'type': 'JWT_SENSITIVE_CLAIMS',
                    'endpoint': endpoint,
                    'user': user_name,
                    'vulnerable': True,
                    'severity': 'MEDIUM',
                    'evidence': {
                        'sensitive_claims': sensitive_claims,
                        'description': 'JWT contiene claims sensibles que no deberían estar expuestos'
                    }
                })
            
            # TEST 2.5: Intentar modificar el token
            finding = self._test_jwt_modification(token, endpoint, user_name)
            if finding['vulnerable']:
                findings.append(finding)
        
        except jwt.exceptions.DecodeError:
            print(f"                 Token no es un JWT válido")
        except Exception as e:
            print(f"                 Error analizando JWT: {str(e)}")
        
        return findings
    
    def _brute_force_jwt_secret(self, token: str) -> Optional[str]:
        """
        Intenta crackear el secreto JWT usando diccionario común.
        
        Returns:
            El secreto si se encuentra, None si no
        """
        for secret in self.common_secrets:
            try:
                # Intentar decodificar con este secreto
                jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                # Si llega aquí, el secreto es correcto
                return secret
            except jwt.exceptions.InvalidSignatureError:
                # Secreto incorrecto, continuar
                continue
            except Exception:
                # Otro error, continuar
                continue
        
        return None
    
    def _check_sensitive_claims(self, payload: Dict) -> List[str]:
        """
        Detecta claims sensibles en el payload del JWT.
        """
        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'api_key', 
            'apikey', 'token', 'credit_card', 'ssn', 'private_key'
        ]
        
        sensitive_found = []
        payload_str = json.dumps(payload).lower()
        
        for keyword in sensitive_keywords:
            if keyword in payload_str:
                sensitive_found.append(keyword)
        
        return sensitive_found
    
    def _test_jwt_modification(self, token: str, endpoint: str, user_name: str) -> Dict[str, Any]:
        """
        Test 2.5: Intentar modificar el JWT y ver si la API lo acepta.
        
        Esto detecta si la API NO está validando la firma del JWT.
        """
        print(f"                 Test: Modificación de JWT")
        
        finding = {
            'type': 'JWT_NO_SIGNATURE_VERIFICATION',
            'endpoint': endpoint,
            'user': user_name,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        try:
            # Decodificar sin verificar
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Modificar el payload (cambiar rol a admin)
            modified_payload = unverified_payload.copy()
            modified_payload['role'] = 'admin'
            modified_payload['is_admin'] = True
            
            # Crear nuevo token SIN FIRMA (firma inválida)
            # Separar las partes del token original
            parts = token.split('.')
            
            # Crear nuevo header y payload
            new_header = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            new_payload = base64.urlsafe_b64encode(
                json.dumps(modified_payload).encode()
            ).decode().rstrip('=')
            
            # Token modificado con firma original (inválida)
            modified_token = f"{new_header}.{new_payload}.{parts[2]}"
            
            # Intentar usar el token modificado
            response = self.requester.get(
                endpoint,
                headers={'Authorization': f'Bearer {modified_token}'}
            )
            
            if response.status_code == 200:
                print(f"                 CRÍTICO: API acepta JWT modificado sin validar firma")
                finding['vulnerable'] = True
                finding['severity'] = 'CRITICAL'
                finding['evidence'] = {
                    'original_role': unverified_payload.get('role', 'N/A'),
                    'modified_role': 'admin',
                    'description': 'La API no valida la firma del JWT, acepta tokens modificados'
                }
            else:
                print(f"                 API rechaza JWT modificado: HTTP {response.status_code}")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def _test_rate_limiting(self, endpoint: str) -> Dict[str, Any]:
        """
        Test 3: Verificar si hay rate limiting en endpoints de autenticación.
        
        Importante para prevenir brute force attacks.
        """
        print(f"             Test: Rate Limiting")
        
        finding = {
            'type': 'NO_RATE_LIMITING',
            'endpoint': endpoint,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        # Número de peticiones a probar
        num_requests = 20
        
        try:
            print(f"                 Enviando {num_requests} peticiones rápidas...")
            
            successful_requests = 0
            start_time = time.time()
            
            for i in range(num_requests):
                response = self.requester.post(
                    endpoint,
                    headers={'Content-Type': 'application/json'},
                    data={'username': f'test{i}', 'password': 'wrong'}
                )
                
                # Contar peticiones que NO fueron bloqueadas por rate limit
                if response.status_code != 429:  # 429 = Too Many Requests
                    successful_requests += 1
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Si todas las peticiones pasaron, NO hay rate limiting
            if successful_requests == num_requests:
                print(f"                 Sin rate limiting detectado")
                print(f"                 {num_requests} peticiones en {duration:.2f}s")
                finding['vulnerable'] = True
                finding['severity'] = 'MEDIUM'
                finding['evidence'] = {
                    'requests_sent': num_requests,
                    'requests_successful': successful_requests,
                    'duration_seconds': duration,
                    'description': 'No se detectó rate limiting, vulnerable a brute force'
                }
            else:
                print(f"                 Rate limiting detectado")
                print(f"                 {successful_requests}/{num_requests} peticiones exitosas")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def _test_user_enumeration(self, endpoint: str) -> Dict[str, Any]:
        """
        Test 4: Detectar enumeración de usuarios.
        
        Verifica si la API revela qué usuarios existen basándose en
        diferentes respuestas para usuarios existentes vs no existentes.
        """
        print(f"             Test: Enumeración de usuarios")
        
        finding = {
            'type': 'USER_ENUMERATION',
            'endpoint': endpoint,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        try:
            # Probar con usuario que probablemente NO existe
            response_nonexistent = self.requester.post(
                endpoint,
                headers={'Content-Type': 'application/json'},
                data={
                    'username': 'nonexistent_user_xyz_12345',
                    'password': 'wrongpassword'
                }
            )
            
            # Probar con usuario común que podría existir
            response_common = self.requester.post(
                endpoint,
                headers={'Content-Type': 'application/json'},
                data={
                    'username': 'admin',
                    'password': 'wrongpassword'
                }
            )
            
            # Comparar respuestas
            different_status = response_nonexistent.status_code != response_common.status_code
            different_message = response_nonexistent.text != response_common.text
            different_length = len(response_nonexistent.text) != len(response_common.text)
            
            if different_status or different_message or different_length:
                print(f"                 Posible enumeración de usuarios")
                print(f"                 Usuario inexistente: HTTP {response_nonexistent.status_code}")
                print(f"                 Usuario común: HTTP {response_common.status_code}")
                
                finding['vulnerable'] = True
                finding['severity'] = 'LOW'
                finding['evidence'] = {
                    'nonexistent_status': response_nonexistent.status_code,
                    'common_status': response_common.status_code,
                    'different_response': different_message,
                    'description': 'La API da respuestas diferentes para usuarios existentes vs no existentes'
                }
            else:
                print(f"                 Respuestas consistentes, no se detectó enumeración")
        
        except Exception as e:
            print(f"                 Error: {str(e)}")
        
        return finding
    
    def generate_report(self) -> str:
        """Genera reporte de hallazgos de autenticación"""
        if not self.findings:
            return f"\n{'='*60}\n  {self.name}: Sin vulnerabilidades\n{'='*60}\n"
        
        report = f"\n{'='*60}\n"
        report += f"{self.name.upper()}\n"
        report += f"{'='*60}\n"
        report += f"Vulnerabilidades encontradas: {len(self.findings)}\n\n"
        
        # Agrupar por tipo
        by_type = {}
        for finding in self.findings:
            ftype = finding['type']
            by_type.setdefault(ftype, []).append(finding)
        
        for ftype, findings_list in by_type.items():
            report += f"\n[{ftype}] - {len(findings_list)} instancia(s)\n"
            for finding in findings_list:
                report += f"  - {finding['endpoint']}\n"
                report += f"    Severidad: {finding['severity']}\n"
                if 'evidence' in finding:
                    report += f"    {finding['evidence'].get('description', '')}\n"
        
        return report
