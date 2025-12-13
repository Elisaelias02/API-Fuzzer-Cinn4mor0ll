from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core.requester import APIRequester

class BaseDetector(ABC):
    """
    Clase base abstracta para todos los detectores de vulnerabilidades.
    
    Todos los módulos (BOLA, Auth, Data Exposure, etc.) heredan de esta clase
    y deben implementar los métodos abstractos.
    """
    
    def __init__(self, requester: APIRequester, name: str):
        self.requester = requester
        self.name = name
        self.findings = []
    
    @abstractmethod
    def run(self, target: Dict, endpoint: Dict) -> List[Dict]:
        """
        Método principal que ejecuta las pruebas del detector.
        
        Args:
            target: Configuración del target (base_url, users, etc.)
            endpoint: Configuración del endpoint a testear
        
        Returns:
            Lista de hallazgos (findings)
        """
        pass
    
    @abstractmethod
    def generate_report(self) -> str:
        """
        Genera un reporte en texto de los hallazgos.
        
        Returns:
            String con el reporte formateado
        """
        pass
    
    def get_findings(self) -> List[Dict]:
        """Retorna todos los hallazgos"""
        return self.findings
    
    def add_finding(self, finding: Dict):
        """Agrega un hallazgo a la lista"""
        self.findings.append(finding)
    
    def clear_findings(self):
        """Limpia los hallazgos (útil para múltiples targets)"""
        self.findings = []
    
    def should_run_for_endpoint(self, endpoint: Dict) -> bool:
        """
        Verifica si este detector debe ejecutarse para el endpoint dado.
        
        Args:
            endpoint: Configuración del endpoint
        
        Returns:
            True si debe ejecutarse, False si no
        """
        test_modules = endpoint.get('test_modules', [])
        # Convertir nombre de clase a snake_case (BOLADetector → bola_detector)
        detector_name = ''.join(['_' + c.lower() if c.isupper() else c 
                                 for c in self.__class__.__name__]).lstrip('_')
        return detector_name in test_modules
