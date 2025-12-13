from typing import List, Dict, Type
from core.requester import APIRequester
from core.config import Config
from modules.base_detector import BaseDetector
import importlib
import inspect

class Orchestrator:
    """
    Orquestador principal que coordina la ejecución de todos los módulos
    de detección sobre los targets configurados.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.detectors: List[BaseDetector] = []
        self.all_findings = []
    
    def _load_detectors(self, requester: APIRequester) -> List[BaseDetector]:
        """
        Carga dinámicamente todos los detectores activos desde la configuración.
        
        Returns:
            Lista de instancias de detectores
        """
        active_modules = self.config.get_active_modules()
        detectors = []
        
        print(f"\nCargando módulos activos: {', '.join(active_modules)}\n")
        
        for module_name in active_modules:
            try:
                # Convertir snake_case a PascalCase
                # bola_detector → BOLADetector
                class_name = ''.join(word.capitalize() for word in module_name.split('_'))
                
                # Importar el módulo dinámicamente
                module = importlib.import_module(f'modules.{module_name}')
                
                # Obtener la clase del detector
                detector_class = getattr(module, class_name)
                
                # Verificar que herede de BaseDetector
                if issubclass(detector_class, BaseDetector):
                    instance = detector_class(requester)
                    detectors.append(instance)
                    print(f" {class_name} cargado")
                else:
                    print(f"{class_name} no hereda de BaseDetector")
            
            except (ImportError, AttributeError) as e:
                print(f"Error cargando {module_name}: {str(e)}")
        
        return detectors
    
    def run_all_tests(self):
        """
        Ejecuta todos los tests sobre todos los targets habilitados.
        """
        targets = self.config.get_enabled_targets()
        
        if not targets:
            print(" No hay targets habilitados en targets.yaml")
            return
        
        print(f"\n{'='*70}")
        print(f"API SECURITY FUZZER - Iniciando análisis")
        print(f"{'='*70}")
        print(f"Targets habilitados: {len(targets)}")
        
        for target in targets:
            self._run_target(target)
        
        # Generar reporte consolidado
        self._generate_consolidated_report()
    
    def _run_target(self, target: Dict):
        """
        Ejecuta todos los tests sobre un target específico.
        
        Args:
            target: Configuración del target
        """
        target_name = target.get('name', 'Unknown')
        base_url = target.get('base_url')
        endpoints = target.get('endpoints', [])
        
        print(f"\n{'='*70}")
        print(f"Target: {target_name}")
        print(f"URL: {base_url}")
        print(f"Endpoints: {len(endpoints)}")
        print(f"{'='*70}")
        
        # Configurar requester para este target
        http_config = self.config.get_http_config()
        requester = APIRequester(
            base_url=base_url,
            timeout=http_config.get('timeout', 10),
            delay=http_config.get('delay', 0.5)
        )
        
        # Cargar detectores
        detectors = self._load_detectors(requester)
        
        # Ejecutar cada detector sobre cada endpoint relevante
        for endpoint in endpoints:
            endpoint_path = endpoint.get('path')
            print(f"\nTesteando endpoint: {endpoint_path}")
            
            for detector in detectors:
                # Verificar si el detector debe ejecutarse para este endpoint
                if detector.should_run_for_endpoint(endpoint):
                    print(f" Ejecutando: {detector.name}")
                    
                    try:
                        findings = detector.run(target, endpoint)
                        
                        if findings:
                            print(f"  {len(findings)} vulnerabilidad(es) encontrada(s)")
                            self.all_findings.extend(findings)
                        else:
                            print(f"Sin vulnerabilidades")
                    
                    except Exception as e:
                        print(f"Error: {str(e)}")
                else:
                    print(f" Saltando: {detector.name} (no configurado para este endpoint)")
        
        # Generar reporte individual del target
        self._generate_target_report(target_name, detectors)
    
    def _generate_target_report(self, target_name: str, detectors: List[BaseDetector]):
        """
        Genera reporte para un target específico.
        """
        print(f"\n{'='*70}")
        print(f"REPORTE: {target_name}")
        print(f"{'='*70}")
        
        total_findings = 0
        
        for detector in detectors:
            findings = detector.get_findings()
            if findings:
                total_findings += len(findings)
                print(detector.generate_report())
        
        if total_findings == 0:
            print("No se encontraron vulnerabilidades en este target")
        else:
            print(f"\nTotal de vulnerabilidades: {total_findings}")
    
    def _generate_consolidated_report(self):
        """
        Genera reporte consolidado de todos los targets.
        """
        print(f"\n{'='*70}")
        print(f"REPORTE CONSOLIDADO - TODOS LOS TARGETS")
        print(f"{'='*70}\n")
        
        if not self.all_findings:
            print(" No se encontraron vulnerabilidades en ningún target")
            return
        
        # Agrupar por severidad
        by_severity = {}
        for finding in self.all_findings:
            severity = finding.get('severity', 'INFO')
            by_severity.setdefault(severity, []).append(finding)
        
        # Mostrar resumen
        print(f"Total de vulnerabilidades: {len(self.all_findings)}\n")
        print("Distribución por severidad:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = len(by_severity.get(severity, []))
            if count > 0:
                icon = '🔥' if severity == 'CRITICAL' else '⚠️' if severity == 'HIGH' else 'ℹ️'
                print(f"   {icon} {severity}: {count}")
        
        # Guardar reportes
        self._save_reports()
    
    def _save_reports(self):
        """
        Guarda reportes en los formatos configurados.
        """
        import json
        from pathlib import Path
        from datetime import datetime
        
        report_config = self.config.get_reporting_config()
        output_dir = Path(report_config.get('output_dir', './reports'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        formats = report_config.get('formats', ['json'])
        
        print(f"\nGuardando reportes en: {output_dir}")
        
        # JSON
        if 'json' in formats:
            json_file = output_dir / f"report_{timestamp}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': timestamp,
                    'total_findings': len(self.all_findings),
                    'findings': self.all_findings
                }, f, indent=2, ensure_ascii=False)
            print(f" JSON: {json_file}")
        
        # TXT
        if 'txt' in formats:
            txt_file = output_dir / f"report_{timestamp}.txt"
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"API Security Fuzzer Report\n")
                f.write(f"Generated: {timestamp}\n")
                f.write(f"{'='*70}\n\n")
                f.write(f"Total findings: {len(self.all_findings)}\n\n")
                
                for idx, finding in enumerate(self.all_findings, 1):
                    f.write(f"[{idx}] {finding.get('endpoint', 'N/A')}\n")
                    f.write(f"    Severity: {finding.get('severity', 'N/A')}\n")
                    f.write(f"    Type: {finding.get('type', 'N/A')}\n")
                    f.write(f"\n")
            
            print(f" TXT: {txt_file}")
        
        # HTML (básico, puedes mejorarlo)
        if 'html' in formats:
            html_file = output_dir / f"report_{timestamp}.html"
            html_content = self._generate_html_report(timestamp)
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML: {html_file}")
    
    def _generate_html_report(self, timestamp: str) -> str:
        """Genera reporte HTML básico"""
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>API Security Fuzzer Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #e74c3c; border-radius: 3px; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #3498db; }}
        .info {{ border-left-color: #95a5a6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>API Security Fuzzer Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2> Resumen</h2>
        <p><strong>Total de vulnerabilidades:</strong> {len(self.all_findings)}</p>
    </div>
    
    <h2>Hallazgos</h2>
"""
        
        for idx, finding in enumerate(self.all_findings, 1):
            severity = finding.get('severity', 'INFO').lower()
            html += f"""
    <div class="finding {severity}">
        <h3>[{idx}] {finding.get('endpoint', 'N/A')}</h3>
        <p><strong>Severidad:</strong> {finding.get('severity', 'N/A')}</p>
        <p><strong>Tipo:</strong> {finding.get('type', 'N/A')}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
