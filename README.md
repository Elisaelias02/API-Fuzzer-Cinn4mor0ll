# API Fuzzer Cinn4mor0ll

**Herramienta profesional de auditoría de seguridad para APIs REST**

Desarrollada por Elisa Elias

---

## Descripción

API  Fuzzer es una herramienta de testing de seguridad diseñada para detectar vulnerabilidades en APIs REST. Implementa técnicas de fuzzing avanzadas siguiendo el OWASP API Security Top 10.

## Características

### Vulnerabilidades Detectadas

- **SQL Injection** (Boolean, Time-based, Union, Error-based)
- **Cross-Site Scripting (XSS)**
- **Command Injection**
- **Path Traversal**
- **XML External Entity (XXE)**
- **Server-Side Request Forgery (SSRF)**
- **Insecure Direct Object Reference (IDOR)**
- **Rate Limiting Issues**
- **Security Headers Missing**
- **Information Disclosure**

---

## Instalación

### Requisitos

- Python 3.8+
- pip

### Instalación Rápida
```bash
# Clonar repositorio
git clone https://github.com/Elisaelias02/API-Fuzzer-Cinn4mor0ll
cd API-Fuzzer-Cinn4mor0ll

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python fuzzer.py --version
```

### Dependencias
```bash
pip install requests colorama
```

---

## Uso Rápido

### Comando Básico
```bash
# Auditoría completa
python fuzzer.py -u https://api.example.com --type all

# Test específico de SQL Injection
python fuzzer.py -u https://api.example.com -e /api/users --type sql -p username

# Con reporte detallado
python fuzzer.py -u https://api.example.com --type all -o report.txt -j report.json -v
```

### Parámetros Principales

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `-u, --url` | URL base de la API (requerido) | `-u https://api.example.com` |
| `-e, --endpoint` | Endpoint específico | `-e /api/users` |
| `-t, --type` | Tipo de test (sql, xss, cmd, path, xxe, ssrf, rate, idor, headers, all) | `--type sql` |
| `-p, --param` | Parámetro a fuzzear | `-p id` |
| `-o, --output` | Guardar reporte en texto | `-o report.txt` |
| `-j, --json` | Guardar reporte en JSON | `-j report.json` |
| `-v, --verbose` | Modo detallado | `-v` |

---

## Ejemplos de Uso

### Test de SQL Injection
```bash
python fuzzer.py -u http://localhost:5000 -e /api/users/search --type sql -p username -v
```

### Test de XSS
```bash
python fuzzer.py -u http://localhost:5000 -e /api/search --type xss -p q -v
```

### Test de Command Injection
```bash
python fuzzer.py -u http://localhost:5000 -e /api/ping --type cmd -p host -v
```

### Test de IDOR
```bash
python fuzzer.py -u http://localhost:5000 -e /api/documents --type idor --id-range 1-100 -v
```

### Test de Rate Limiting
```bash
python fuzzer.py -u http://localhost:5000 -e /api/public/data --type rate --requests 100
```

### Con Burp Suite (Proxy)
```bash
python fuzzer.py -u https://api.example.com --proxy http://127.0.0.1:8080 --no-ssl-verify --type all -v
```

### Con Autenticación
```bash
python fuzzer.py -u https://api.example.com --headers "Authorization: Bearer TOKEN" --type all
```

---

##  VulnAPI Lab - API de Práctica

Incluye una API vulnerable para practicar:

### Iniciar VulnAPI Lab
```bash
# Terminal 1: Iniciar API vulnerable
python VulnAPI.py

# API corriendo en http://localhost:5000
```

### Probar el Fuzzer contra VulnAPI
```bash
# Terminal 2: Ejecutar fuzzer
python fuzzer.py -u http://localhost:5000 --type all -o test_results.txt -v
```

### Endpoints Vulnerables

- `/api/users/search?username=` - SQL Injection
- `/api/search?q=` - XSS
- `/api/ping?host=` - Command Injection
- `/api/files?path=` - Path Traversal
- `/api/parse-xml` - XXE
- `/api/fetch?url=` - SSRF
- `/api/documents/<id>` - IDOR
- `/api/public/data` - Sin Rate Limiting

---

## Configuración Avanzada

### Todos los Parámetros
```bash
python fuzzer.py -h

Opciones principales:
  -u, --url URL              URL base de la API
  -e, --endpoint PATH        Endpoint (default: /)
  -m, --method METHOD        Método HTTP (GET, POST, PUT, DELETE, PATCH)
  -p, --param NAME           Parámetro a fuzzear (default: id)
  -t, --type TYPE            Tipo de test (sql, xss, cmd, path, xxe, ssrf, rate, idor, headers, all)

Output:
  -o, --output FILE          Archivo de salida (texto)
  -j, --json FILE            Archivo de salida (JSON)
  -v, --verbose              Modo verbose

Red:
  --timeout SECONDS          Timeout (default: 10)
  --delay SECONDS            Delay entre requests (default: 0.1)
  --proxy URL                Proxy URL (ej: http://127.0.0.1:8080)
  --no-ssl-verify            Deshabilitar verificación SSL
  --headers HEADERS          Headers personalizados

Específicos:
  --requests NUM             Requests para rate limiting (default: 100)
  --id-range RANGE           Rango IDs para IDOR (ej: 1-100)
  --threads NUM              Número de threads (default: 5)
```

---

## Estructura de Reportes

### Reporte en Texto
```
================================================================================
                    API SECURITY AUDIT REPORT
================================================================================

INFORMACIÓN GENERAL
================================================================================
Fecha/Hora:          2024-12-30 15:30:45
Target:              http://localhost:5000
Total Tests:         150
Vulnerabilidades:    12
SSL Verification:    Enabled

RESUMEN POR SEVERIDAD
================================================================================
Critical:            2
High:                4
Medium:              5
Low:                 1

[CRITICAL] - 2 Hallazgos
--------------------------------------------------------------------------------

#1 - Command Injection
Endpoint:        http://localhost:5000/api/ping?host=; sleep 5
Método:          GET
Severidad:       Critical
Status Code:     200
Response Time:   5.234s
Payload:         ; sleep 5
Detalles:        Time-based Command Injection - Delay: 5.23s
...
```

### Reporte en JSON
```json
{
  "scan_info": {
    "timestamp": "2024-12-30T15:30:45",
    "target": "http://localhost:5000",
    "total_tests": 150,
    "vulnerabilities_found": 12
  },
  "summary": {
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1
  },
  "vulnerabilities": [
    {
      "endpoint": "http://localhost:5000/api/ping",
      "method": "GET",
      "payload": "; sleep 5",
      "vulnerability_type": "Command Injection",
      "severity": "Critical",
      "details": "Time-based Command Injection detected",
      "timestamp": "2024-12-30T15:30:45"
    }
  ]
}
```

---

##  Arquitectura
```
┌─────────────────────────────────────────────────────┐
│                 API Security Fuzzer                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. PayloadGenerator  →  Payloads por tipo         │
│  2. APIFuzzer         →  Motor de fuzzing          │
│  3. Response Analyzer →  Detección de vulns        │
│  4. Result Storage    →  Almacenamiento thread-safe│
│  5. Report Generator  →  Reportes texto/JSON       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Flujo:**
1. Cargar payloads según tipo de test
2. Enviar requests con payloads
3. Analizar respuestas (patterns, time, status)
4. Detectar y clasificar vulnerabilidades
5. Generar reportes profesionales


---

## Contacto

**SecureAegis**
- 🌐 Website: [https://secureaegis.net](https://secureaegis.net)
- 📧 Email: elisaelias@secureaegis.net

---

<div align="center">

**Desarrollado con ❤️ por Cinn4mor0ll**

Hecho en 🇲🇽 para la comunidad de ciberseguridad

</div>
