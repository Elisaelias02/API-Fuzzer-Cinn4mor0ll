import re
from typing import List, Dict, Any, Optional
from core.requester import APIRequester
import json

class BOLADetector:
    """
    Detector de vulnerabilidades BOLA (Broken Object Level Authorization).
    
    Estrategia:
    1. Identificar endpoints con identificadores (IDs)
    2. Probar acceso a recursos con diferentes credenciales
    3. Detectar accesos no autorizados comparando respuestas
    """
    
    def __init__(self, requester: APIRequester):
        self.requester = requester
        self.findings = []  # Almacena vulnerabilidades encontradas
    
    def _extract_id_from_endpoint(self, endpoint: str) -> Optional[str]:
        """
        Extrae el ID de un endpoint.
        
        Ejemplos:
            /api/users/123 → 123
            /api/orders/abc-def-123 → abc-def-123
            /api/documents/5f8a7b2c → 5f8a7b2c
        """
        # Buscar patrones comunes de IDs
        patterns = [
            r'/(\d+)(?:/|$)',           # IDs numéricos: /123
            r'/([a-f0-9-]{36})(?:/|$)', # UUIDs: /550e8400-e29b-41d4-a716-446655440000
            r'/([a-z0-9-_]+)(?:/|$)',   # IDs alfanuméricos: /user-abc123
        ]
        
        for pattern in patterns:
            match = re.search(pattern, endpoint)
            if match:
                return match.group(1)
        
        return None
    
    def _compare_responses(self, response1: Dict, response2: Dict, 
                          exclude_fields: List[str] = None) -> float:
        """
        Compara dos respuestas JSON y retorna un score de similitud (0-1).
        
        Args:
            response1: Primera respuesta (usuario legítimo)
            response2: Segunda respuesta (atacante)
            exclude_fields: Campos que naturalmente serán diferentes (timestamps, etc.)
        
        Returns:
            Float entre 0 (totalmente diferentes) y 1 (idénticas)
        """
        exclude_fields = exclude_fields or ['timestamp', 'request_id', 'date']
        
        def clean_dict(d: Dict, exclude: List[str]) -> Dict:
            """Remueve campos que varían naturalmente"""
            return {k: v for k, v in d.items() if k not in exclude}
        
        clean1 = clean_dict(response1, exclude_fields)
        clean2 = clean_dict(response2, exclude_fields)
        
        # Campos en común
        common_keys = set(clean1.keys()) & set(clean2.keys())
        if not common_keys:
            return 0.0
        
        # Contar cuántos valores coinciden
        matching_values = sum(1 for k in common_keys if clean1[k] == clean2[k])
        
        return matching_values / len(common_keys)
    
    def _has_sensitive_data(self, response_data: Dict) -> List[str]:
        """
        Detecta si la respuesta contiene datos sensibles.
        
        Returns:
            Lista de campos sensibles encontrados
        """
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\+?[\d\s\-\(\)]{10,}',
            'ssn': r'\d{3}-\d{2}-\d{4}',
            'credit_card': r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}',
            'password': r'password|passwd|pwd',
            'token': r'token|api_key|apikey|secret',
        }
        
        found_sensitive = []
        response_str = json.dumps(response_data).lower()
        
        for field_type, pattern in sensitive_patterns.items():
            if re.search(pattern, response_str, re.IGNORECASE):
                found_sensitive.append(field_type)
        
        return found_sensitive
    
    def test_bola_basic(self, endpoint: str, user1_auth: Dict, user2_auth: Dict,
                       user1_id: str, user2_id: str) -> Dict[str, Any]:
        """
        Test básico de BOLA: Usuario B intenta acceder al recurso de Usuario A.
        
        Args:
            endpoint: Template del endpoint (ej: /api/users/{id})
            user1_auth: Headers de autenticación del Usuario A
            user2_auth: Headers de autenticación del Usuario B
            user1_id: ID del recurso de Usuario A
            user2_id: ID del recurso de Usuario B
        
        Returns:
            Diccionario con resultado del test
        """
        print(f"\nTesting BOLA en: {endpoint}")
        print(f"   Usuario A ID: {user1_id}")
        print(f"   Usuario B ID: {user2_id}")
        
        # 1. Usuario A accede a SU PROPIO recurso (comportamiento legítimo)
        endpoint_user1 = endpoint.replace('{id}', user1_id)
        response_legitimate = self.requester.get(endpoint_user1, headers=user1_auth)
        
        print(f"   Usuario A accede a su recurso: HTTP {response_legitimate.status_code}")
        
        # 2. Usuario B intenta acceder al recurso de Usuario A (ATAQUE BOLA)
        response_attack = self.requester.get(endpoint_user1, headers=user2_auth)
        
        print(f"   Usuario B intenta acceder a recurso de A: HTTP {response_attack.status_code}")
        
        # 3. Análisis de la respuesta
        finding = {
            'endpoint': endpoint,
            'victim_id': user1_id,
            'attacker_id': user2_id,
            'vulnerable': False,
            'severity': 'INFO',
            'evidence': {}
        }
        
        # ¿El ataque fue exitoso?
        if response_attack.status_code == 200:
            print("   ALERTA: Usuario B obtuvo HTTP 200")
            
            try:
                data_legitimate = response_legitimate.json()
                data_attack = response_attack.json()
                
                # Comparar las respuestas
                similarity = self._compare_responses(data_legitimate, data_attack)
                sensitive_fields = self._has_sensitive_data(data_attack)
                
                print(f"   Similitud de respuestas: {similarity*100:.1f}%")
                
                # Si las respuestas son muy similares, es BOLA
                if similarity > 0.7:  # 70% de similitud
                    finding['vulnerable'] = True
                    finding['severity'] = 'CRITICAL' if sensitive_fields else 'HIGH'
                    finding['evidence'] = {
                        'similarity_score': similarity,
                        'sensitive_data_exposed': sensitive_fields,
                        'legitimate_response': data_legitimate,
                        'attack_response': data_attack
                    }
                    
                    print(f" VULNERABILIDAD BOLA CONFIRMADA")
                    print(f" Severidad: {finding['severity']}")
                    if sensitive_fields:
                        print(f" Datos sensibles expuestos: {', '.join(sensitive_fields)}")
                    
                    self.findings.append(finding)
                else:
                    print(f" Respuestas diferentes, posible filtrado correcto")
            
            except json.JSONDecodeError:
                print("  Respuesta no es JSON válido")
        
        elif response_attack.status_code in [401, 403]:
            print(f"  Protección correcta: HTTP {response_attack.status_code}")
        
        elif response_attack.status_code == 404:
            print(f"  Recurso no encontrado o acceso denegado silenciosamente")
        
        else:
            print(f" Respuesta inusual: HTTP {response_attack.status_code}")
        
        return finding
    
    def test_bola_enumeration(self, endpoint: str, auth: Dict, 
                             start_id: int, end_id: int) -> List[Dict]:
        """
        Test de enumeración BOLA: Probar múltiples IDs secuenciales.
        
        Útil para encontrar recursos accesibles sin autorización.
        
        Args:
            endpoint: Template del endpoint (ej: /api/invoices/{id})
            auth: Headers de autenticación del atacante
            start_id: ID inicial
            end_id: ID final
        """
        print(f"\n Enumerando IDs de {start_id} a {end_id} en {endpoint}")
        
        accessible_resources = []
        
        for test_id in range(start_id, end_id + 1):
            test_endpoint = endpoint.replace('{id}', str(test_id))
            response = self.requester.get(test_endpoint, headers=auth)
            
            if response.status_code == 200:
                print(f" ID {test_id}: ACCESIBLE")
                
                try:
                    data = response.json()
                    sensitive = self._has_sensitive_data(data)
                    
                    accessible_resources.append({
                        'id': test_id,
                        'endpoint': test_endpoint,
                        'sensitive_data': sensitive,
                        'data': data
                    })
                    
                    if sensitive:
                        print(f"  Contiene: {', '.join(sensitive)}")
                
                except json.JSONDecodeError:
                    accessible_resources.append({
                        'id': test_id,
                        'endpoint': test_endpoint,
                        'raw_response': response.text
                    })
            
            elif response.status_code in [401, 403]:
                print(f"ID {test_id}: Protegido")
            
            elif response.status_code == 404:
                print(f"ID {test_id}: No existe")
        
        print(f"\nRecursos accesibles encontrados: {len(accessible_resources)}")
        
        if accessible_resources:
            finding = {
                'endpoint': endpoint,
                'vulnerable': True,
                'severity': 'HIGH',
                'type': 'BOLA_ENUMERATION',
                'accessible_resources': accessible_resources,
                'total_accessible': len(accessible_resources)
            }
            self.findings.append(finding)
        
        return accessible_resources
    
    def get_findings(self) -> List[Dict]:
        """Retorna todas las vulnerabilidades encontradas"""
        return self.findings
    
    def generate_report(self) -> str:
        """Genera un reporte legible de las vulnerabilidades encontradas"""
        if not self.findings:
            return " No se encontraron vulnerabilidades BOLA"
        
        report = f"\n{'='*60}\n"
        report += f"REPORTE DE VULNERABILIDADES BOLA\n"
        report += f"{'='*60}\n\n"
        report += f"Total de vulnerabilidades: {len(self.findings)}\n\n"
        
        for idx, finding in enumerate(self.findings, 1):
            report += f"[{idx}] {finding['endpoint']}\n"
            report += f"    Severidad: {finding['severity']}\n"
            
            if finding.get('type') == 'BOLA_ENUMERATION':
                report += f"    Tipo: Enumeración BOLA\n"
                report += f"    Recursos accesibles: {finding['total_accessible']}\n"
            else:
                report += f"    Víctima ID: {finding['victim_id']}\n"
                report += f"    Atacante ID: {finding['attacker_id']}\n"
                
                if 'evidence' in finding:
                    evidence = finding['evidence']
                    report += f"    Similitud: {evidence['similarity_score']*100:.1f}%\n"
                    
                    if evidence['sensitive_data_exposed']:
                        report += f"    Datos sensibles: {', '.join(evidence['sensitive_data_exposed'])}\n"
            
            report += "\n"
        
        return report
