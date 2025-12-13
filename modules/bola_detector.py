from typing import Dict, List, Any
from modules.base_detector import BaseDetector
from core.requester import APIRequester
import re
import json

class BOLADetector(BaseDetector):
    """
    Detector de vulnerabilidades BOLA (Broken Object Level Authorization).
    Hereda de BaseDetector.
    """
    
    def __init__(self, requester: APIRequester):
        super().__init__(requester, "BOLA Detector")
    
    def run(self, target: Dict, endpoint: Dict) -> List[Dict]:
        """
        Ejecuta las pruebas BOLA sobre el endpoint.
        
        Args:
            target: Configuración del target (usuarios, base_url, etc.)
            endpoint: Configuración del endpoint a testear
        
        Returns:
            Lista de hallazgos
        """
        findings = []
        users = target.get('users', [])
        
        if len(users) < 2:
            print(" Se necesitan al menos 2 usuarios para test BOLA")
            return findings
        
        endpoint_path = endpoint.get('path')
        
        # Test BOLA básico: Usuario A vs Usuario B
        user_a = users[0]
        user_b = users[1]
        
        finding = self._test_bola_basic(
            endpoint_path,
            {'Authorization': user_a['token']},
            {'Authorization': user_b['token']},
            user_a['id'],
            user_b['id']
        )
        
        if finding['vulnerable']:
            findings.append(finding)
        
        # Test de enumeración (opcional, solo con primer usuario)
        if '{id}' in endpoint_path:
            enum_findings = self._test_bola_enumeration(
                endpoint_path,
                {'Authorization': user_a['token']},
                start_id=1,
                end_id=10  # Limitar para no saturar
            )
            findings.extend(enum_findings)
        
        return findings
    
    def _test_bola_basic(self, endpoint: str, user1_auth: Dict, user2_auth: Dict,
                        user1_id: str, user2_id: str) -> Dict[str, Any]:
        """
        Test básico de BOLA (igual que antes, pero retorna finding directo)
        """
        endpoint_user1 = endpoint.replace('{id}', user1_id)
        response_legitimate = self.requester.get(endpoint_user1, headers=user1_auth)
        response_attack = self.requester.get(endpoint_user1, headers=user2_auth)
        
        finding = {
            'type': 'BOLA',
            'endpoint': endpoint,
            'victim_id': user1_id,
            'attacker_id': user2_id,
            'vulnerable': False,
            'severity': 'INFO'
        }
        
        if response_attack.status_code == 200:
            try:
                data_legitimate = response_legitimate.json()
                data_attack = response_attack.json()
                
                similarity = self._compare_responses(data_legitimate, data_attack)
                sensitive_fields = self._has_sensitive_data(data_attack)
                
                if similarity > 0.7:
                    finding['vulnerable'] = True
                    finding['severity'] = 'CRITICAL' if sensitive_fields else 'HIGH'
                    finding['evidence'] = {
                        'similarity_score': similarity,
                        'sensitive_data_exposed': sensitive_fields
                    }
            
            except json.JSONDecodeError:
                pass
        
        return finding
    
    def _test_bola_enumeration(self, endpoint: str, auth: Dict, 
                              start_id: int, end_id: int) -> List[Dict]:
        """
        Test de enumeración BOLA
        """
        findings = []
        accessible_count = 0
        
        for test_id in range(start_id, end_id + 1):
            test_endpoint = endpoint.replace('{id}', str(test_id))
            response = self.requester.get(test_endpoint, headers=auth)
            
            if response.status_code == 200:
                accessible_count += 1
        
        if accessible_count > 0:
            findings.append({
                'type': 'BOLA_ENUMERATION',
                'endpoint': endpoint,
                'vulnerable': True,
                'severity': 'HIGH',
                'accessible_resources': accessible_count,
                'total_tested': end_id - start_id + 1
            })
        
        return findings
    
    def _compare_responses(self, response1: Dict, response2: Dict) -> float:
        """Compara dos respuestas JSON (igual que antes)"""
        # [código igual que antes]
        clean1 = {k: v for k, v in response1.items() if k not in ['timestamp', 'request_id']}
        clean2 = {k: v for k, v in response2.items() if k not in ['timestamp', 'request_id']}
        
        common_keys = set(clean1.keys()) & set(clean2.keys())
        if not common_keys:
            return 0.0
        
        matching_values = sum(1 for k in common_keys if clean1[k] == clean2[k])
        return matching_values / len(common_keys)
    
    def _has_sensitive_data(self, response_data: Dict) -> List[str]:
        """Detecta datos sensibles (igual que antes)"""
        # [código igual que antes]
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\+?[\d\s\-\(\)]{10,}',
            'ssn': r'\d{3}-\d{2}-\d{4}',
            'password': r'password|passwd|pwd',
            'token': r'token|api_key|secret',
        }
        
        found_sensitive = []
        response_str = json.dumps(response_data).lower()
        
        for field_type, pattern in sensitive_patterns.items():
            if re.search(pattern, response_str, re.IGNORECASE):
                found_sensitive.append(field_type)
        
        return found_sensitive
    
    def generate_report(self) -> str:
        """Genera reporte de hallazgos BOLA"""
        if not self.findings:
            return f"\n{'='*60}\n{self.name}: Sin vulnerabilidades\n{'='*60}\n"
        
        report = f"\n{'='*60}\n"
        report += f"{self.name.upper()}\n"
        report += f"{'='*60}\n"
        report += f"Vulnerabilidades encontradas: {len(self.findings)}\n\n"
        
        for idx, finding in enumerate(self.findings, 1):
            report += f"[{idx}] {finding['endpoint']}\n"
            report += f"    Severidad: {finding['severity']}\n"
            report += f"    Tipo: {finding['type']}\n\n"
        
        return report
