import yaml
from typing import Dict, List, Any
from pathlib import Path

class Config:
    """
    Carga y gestiona la configuración del fuzzer desde archivos YAML.
    """
    
    def __init__(self, config_file: str = "config.yaml", targets_file: str = "targets.yaml"):
        self.config_file = Path(config_file)
        self.targets_file = Path(targets_file)
        
        self.config = self._load_yaml(self.config_file)
        self.targets = self._load_yaml(self.targets_file)
    
    def _load_yaml(self, file_path: Path) -> Dict:
        """Carga un archivo YAML"""
        if not file_path.exists():
            raise FileNotFoundError(f"Archivo de configuración no encontrado: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Obtiene un valor de configuración usando notación de punto.
        
        Ejemplo:
            config.get('http.timeout') → 10
            config.get('modules.bola_detector') → True
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default
    
    def get_active_modules(self) -> List[str]:
        """Retorna lista de módulos activos"""
        modules = self.config.get('modules', {})
        return [name for name, enabled in modules.items() if enabled]
    
    def get_enabled_targets(self) -> List[Dict]:
        """Retorna solo los targets habilitados"""
        all_targets = self.targets.get('targets', [])
        return [t for t in all_targets if t.get('enabled', False)]
    
    def get_http_config(self) -> Dict:
        """Retorna configuración HTTP"""
        return self.config.get('http', {})
    
    def get_reporting_config(self) -> Dict:
        """Retorna configuración de reportes"""
        return self.config.get('reporting', {})
