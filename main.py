#!/usr/bin/env python3
"""
API Security Fuzzer - Main Entry Point

Autor: Elisa Elias (AEGIS / H4ck The World)

Modos de uso:
    python main.py                                # Usar config.yaml y targets.yaml
    python main.py --interactive                  # Modo interactivo (configurar target manualmente)
    python main.py --quick-scan <URL> --token <TOKEN> # Quick scan rápido
    python main.py --url <URL> --token <TOKEN> --endpoints /api/users,/api/orders # Custom endpoints
"""

import argparse
import sys
from pathlib import Path

# Agregar directorio raíz al path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.orchestrator import Orchestrator
from utils.interactive import InteractiveConfigurator, QuickScanConfigurator
import tempfile
import yaml
import os

# ASCII Art de Cinnamoroll (Reutilizado del módulo interactive.py)
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
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠑⠒⠒⠒⠒⠒⠒⠒⠒⠒⠋⡀⠐\u200b⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

def parse_arguments():
    """Parse argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='API Security Fuzzer - Detección de vulnerabilidades en APIs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:

  # Modo normal con archivos YAML
  python main.py --config config.yaml --targets targets.yaml

  # Modo interactivo (asistente paso a paso)
  python main.py --interactive

  # Quick scan (escaneo rápido)
  python main.py --quick-scan https://api.example.com --token eyJhbG...

  # Scan personalizado con endpoints específicos
  python main.py --url https://api.example.com --token eyJhbG... \\
                 --endpoints /api/users/{id},/api/orders/{id}

  # Quick scan sin autenticación
  python main.py --quick-scan https://api.example.com --no-auth
        """
    )
    
    # Grupo: Archivos de configuración (modo tradicional)
    config_group = parser.add_argument_group('Configuración desde archivos')
    config_group.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Archivo de configuración del fuzzer (default: config.yaml)'
    )
    config_group.add_argument(
        '--targets',
        type=str,
        default='targets.yaml',
        help='Archivo de configuración de targets (default: targets.yaml)'
    )
    
    # Grupo: Modo interactivo
    interactive_group = parser.add_argument_group('Modo interactivo')
    interactive_group.add_argument(
        '--interactive',
        action='store_true',
        help='Iniciar asistente interactivo para configurar target'
    )
    interactive_group.add_argument(
        '--save-config',
        type=str,
        help='Guardar configuración interactiva en archivo (ej: my_target.yaml)'
    )
    
    # Grupo: Quick scan
    quick_group = parser.add_argument_group('Quick Scan (escaneo rápido)')
    quick_group.add_argument(
        '--quick-scan',
        type=str,
        metavar='URL',
        help='URL base del API para escaneo rápido'
    )
    quick_group.add_argument(
        '--url',
        type=str,
        help='URL base del API (alternativa a --quick-scan)'
    )
    quick_group.add_argument(
        '--token',
        type=str,
        help='Token de autenticación (Bearer token sin prefijo)'
    )
    quick_group.add_argument(
        '--user-id',
        type=str,
        default='1',
        help='ID del usuario para tests (default: 1)'
    )
    quick_group.add_argument(
        '--no-auth',
        action='store_true',
        help='Escanear sin autenticación'
    )
    quick_group.add_argument(
        '--endpoints',
        type=str,
        help='Endpoints a testear, separados por coma (ej: /api/users,/api/orders/{id})'
    )
    
    # Otros
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

def run_interactive_mode(args):
    """Ejecuta el modo interactivo"""
    configurator = InteractiveConfigurator()
    target_config = configurator.start()
    
    # ¿Guardar configuración?
    if args.save_config:
        configurator.save_to_file(args.save_config)
    else:
        # Reutilizamos los métodos de _get_input y _get_yes_no del objeto configurator
        if configurator._get_yes_no("\n¿Quieres guardar esta configuración?", default=True):
            filename = configurator._get_input(
                "Nombre del archivo",
                default="custom_target.yaml"
            )
            configurator.target = target_config['targets'][0]
            configurator.save_to_file(filename)
    
    # Crear archivo temporal con la configuración
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
    yaml.dump(target_config, temp_file, default_flow_style=False)
    temp_file.close()
    
    return temp_file.name

def run_quick_scan(args):
    """Ejecuta quick scan con parámetros de línea de comandos"""
    url = args.quick_scan or args.url
    
    if not url:
        print("Error: Debes proporcionar --quick-scan o --url")
        sys.exit(1)
    
    # Determinar token
    token = None if args.no_auth else args.token
    
    if not token and not args.no_auth:
        print("Advertencia: No se proporcionó token. Usa --token o --no-auth")
        print("Continuando sin autenticación...")
    
    print(f"\n[SCANNER INICIADO] Quick Scan Mode")
    print(f"   URL: {url}")
    print(f"   Auth: {'Deshabilitado' if args.no_auth else 'Bearer Token'}")
    
    # Crear configuración
    target_config = QuickScanConfigurator.create_target(
        url=url,
        token=token,
        user_id=args.user_id
    )
    
    # Si se especificaron endpoints personalizados
    if args.endpoints:
        custom_endpoints = []
        for ep in args.endpoints.split(','):
            ep = ep.strip()
            # Asignación de módulos de prueba, asegurando que se testee todo lo relevante
            modules = []
            if '{id}' in ep or '{uuid}' in ep:
                 modules.append('bola_detector')
            if 'auth' in ep.lower() or 'login' in ep.lower() or not args.no_auth:
                 modules.append('auth_detector')
            modules.append('data_exposure_detector')

            custom_endpoints.append({
                'path': ep,
                'methods': ['GET'],
                'auth_required': not args.no_auth,
                'test_modules': modules
            })
        target_config['targets'][0]['endpoints'] = custom_endpoints
        print(f"   Endpoints personalizados: {len(custom_endpoints)}")
    
    # Crear archivo temporal
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
    yaml.dump(target_config, temp_file, default_flow_style=False)
    temp_file.close()
    
    return temp_file.name

def main():
    """Función principal"""
    
    # Banner Cinnamoroll y Autoría Elisa Elias
    print(CINNAGENERATED_BANNER)
    print("="*70)
    print("API SECURITY FUZZER v1.0 - Detección de Vulnerabilidades en APIs")
    print("Módulos: BOLA | Auth | Data Exposure")
    print("Autor: Elisa Elias (AEGIS / H4ck The World)")
    print("="*70)
    
    # Parsear argumentos
    args = parse_arguments()
    
    try:
        targets_file = args.targets
        
        # MODO 1: Interactivo
        if args.interactive:
            print("[MODO] Iniciando modo interactivo...")
            targets_file = run_interactive_mode(args)
        
        # MODO 2: Quick Scan
        elif args.quick_scan or args.url:
            targets_file = run_quick_scan(args)
        
        # MODO 3: Normal (archivos YAML)
        else:
            print(f"[MODO] Modo normal - usando archivos de configuración")
        
        # Cargar configuración
        print(f"\n[INFO] Cargando configuración...")
        print(f"   Config: {args.config}")
        print(f"   Targets: {targets_file}")
        
        config = Config(
            config_file=args.config,
            targets_file=targets_file
        )
        
        # Crear orquestador
        orchestrator = Orchestrator(config)
        
        # Ejecutar todos los tests
        orchestrator.run_all_tests()
        
        print(f"\n{'='*70}")
        print("[COMPLETADO] Análisis finalizado")
        print(f"{'='*70}\n")
        
        # Limpiar archivo temporal si fue creado
        if args.interactive or args.quick_scan or args.url:
            try:
                os.unlink(targets_file)
            except Exception:
                pass
    
    except FileNotFoundError as e:
        print(f"\n[ERROR] Archivo no encontrado: {str(e)}")
        print("Consejo: Usa --interactive para configurar un target manualmente.")
        print("Consejo: O usa --quick-scan <URL> para un escaneo rápido.")
        sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n[INTERRUPCION] Análisis detenido por el usuario.")
        sys.exit(0)
    
    except Exception as e:
        print(f"\n[ERROR] Error inesperado: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
