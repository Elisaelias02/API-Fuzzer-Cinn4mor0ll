#!/usr/bin/env python3
"""
API Security Fuzzer - Main Entry Point

Fuzzer modular de seguridad para APIs REST.
Detecta vulnerabilidades: BOLA, Broken Auth, Data Exposure, etc.

Autor: cinn4mor0ll

Uso:
    python main.py                              # Ejecutar con configuración por defecto
    python main.py --config custom.yaml --targets prod.yaml
"""

import argparse
import sys
from pathlib import Path

# Agregar directorio raíz al path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.orchestrator import Orchestrator

def parse_arguments():
    """Parse argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='API Security Fuzzer - Detección de vulnerabilidades en APIs'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Archivo de configuración del fuzzer (default: config.yaml)'
    )
    
    parser.add_argument(
        '--targets',
        type=str,
        default='targets.yaml',
        help='Archivo de configuración de targets (default: targets.yaml)'
    )
    
    parser.add_argument(
        '--modules',
        type=str,
        nargs='+',
        help='Módulos específicos a ejecutar (ej: bola_detector auth_detector)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Directorio de salida para reportes'
    )
    
    return parser.parse_args()

def main():
    """Función principal"""
    
    # Banner ASCII personalizado por cinn4mor0ll
    print("""
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
    """)
    print("        API Security Fuzzer v1.0 - Detección de Vulnerabilidades en APIs")
    print("        Módulos: BOLA | Auth | Data Exposure")
    
    # Parsear argumentos
    args = parse_arguments()
    
    try:
        # Cargar configuración
        print(f"Cargando configuración...")
        print(f"   Config: {args.config}")
        print(f"   Targets: {args.targets}")
        
        config = Config(
            config_file=args.config,
            targets_file=args.targets
        )
        
        # Crear orquestador
        orchestrator = Orchestrator(config)
        
        # Ejecutar todos los tests
        orchestrator.run_all_tests()
        
        print(f"\n{'='*70}")
        print("Análisis completado")
        print(f"{'='*70}\n")
    
    except FileNotFoundError as e:
        print(f"\nError: {str(e)}")
        print("Asegúrate de tener los archivos config.yaml y targets.yaml")
        sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\nAnálisis interrumpido por el usuario")
        sys.exit(0)
    
    except Exception as e:
        print(f"\nError inesperado: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
