#!/usr/bin/env python3
"""
VulnAPI Lab - API Vulnerable para Práctica de Fuzzing
Autor: Cinn4mor0ll
"""

from flask import Flask, request, jsonify, make_response
import sqlite3
import subprocess
import os
import time
from functools import wraps
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnerable_key_123'

# Deshabilitar CORS para testing
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    # Intencionalmente sin headers de seguridad para que el fuzzer los detecte
    return response

# ============================================
# BASE DE DATOS VULNERABLE
# ============================================

def init_db():
    """Inicializa la base de datos de prueba"""
    conn = sqlite3.connect('vulnapi.db')
    c = conn.cursor()
    
    # Tabla de usuarios
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, 
                  username TEXT, 
                  password TEXT,
                  email TEXT,
                  role TEXT)''')
    
    # Tabla de documentos
    c.execute('''CREATE TABLE IF NOT EXISTS documents
                 (id INTEGER PRIMARY KEY,
                  title TEXT,
                  content TEXT,
                  owner_id INTEGER)''')
    
    # Insertar datos de prueba
    users_data = [
        (1, 'admin', 'admin123', 'admin@vulnapi.local', 'admin'),
        (2, 'user1', 'password1', 'user1@vulnapi.local', 'user'),
        (3, 'user2', 'password2', 'user2@vulnapi.local', 'user'),
        (4, 'testuser', 'test123', 'test@vulnapi.local', 'user'),
        (5, 'guest', 'guest', 'guest@vulnapi.local', 'guest'),
    ]
    
    c.execute("DELETE FROM users")
    c.executemany('INSERT INTO users VALUES (?,?,?,?,?)', users_data)
    
    docs_data = [
        (1, 'Public Document', 'This is a public document', 1),
        (2, 'Private Document', 'This is private user1 data', 2),
        (3, 'Secret Document', 'This is secret user2 data', 3),
        (4, 'Confidential', 'Confidential information here', 1),
        (5, 'Test Doc', 'Testing document', 4),
    ]
    
    c.execute("DELETE FROM documents")
    c.executemany('INSERT INTO documents VALUES (?,?,?,?)', docs_data)
    
    conn.commit()
    conn.close()

# ============================================
# ENDPOINTS VULNERABLES
# ============================================

@app.route('/')
def index():
    """Página de inicio con información de la API"""
    return jsonify({
        "name": "VulnAPI Lab",
        "version": "1.0",
        "description": "API vulnerable para práctica de fuzzing",
        "warning": "SOLO PARA TESTING - NO USAR EN PRODUCCIÓN",
        "endpoints": {
            "sql_injection": [
                "/api/users/search?username=<value>",
                "/api/users/<id>",
                "/api/login (POST)"
            ],
            "xss": [
                "/api/search?q=<value>",
                "/api/comment (POST)"
            ],
            "command_injection": [
                "/api/ping?host=<value>",
                "/api/dns?domain=<value>"
            ],
            "path_traversal": [
                "/api/files?path=<value>",
                "/api/download?file=<value>"
            ],
            "xxe": [
                "/api/parse-xml (POST)"
            ],
            "ssrf": [
                "/api/fetch?url=<value>",
                "/api/webhook?callback=<value>"
            ],
            "idor": [
                "/api/documents/<id>",
                "/api/profile/<id>"
            ],
            "rate_limiting": [
                "/api/public/data"
            ]
        }
    }), 200

# ============================================
# 1. SQL INJECTION VULNERABILITIES
# ============================================

@app.route('/api/users/search', methods=['GET'])
def search_users():
    """VULNERABLE: SQL Injection en parámetro de búsqueda"""
    username = request.args.get('username', '')
    
    try:
        conn = sqlite3.connect('vulnapi.db')
        c = conn.cursor()
        
        # VULNERABLE: Concatenación directa de strings
        query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{username}%'"
        c.execute(query)
        
        results = []
        for row in c.fetchall():
            results.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3]
            })
        
        conn.close()
        return jsonify({"results": results}), 200
        
    except Exception as e:
        # Expone errores SQL detallados
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """VULNERABLE: SQL Injection en parámetro de ruta"""
    try:
        conn = sqlite3.connect('vulnapi.db')
        c = conn.cursor()
        
        # VULNERABLE: Sin validación del input
        query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
        c.execute(query)
        
        row = c.fetchone()
        if row:
            user = {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3]
            }
            conn.close()
            return jsonify(user), 200
        else:
            conn.close()
            return jsonify({"error": "User not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """VULNERABLE: SQL Injection en login"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    try:
        conn = sqlite3.connect('vulnapi.db')
        c = conn.cursor()
        
        # VULNERABLE: Authentication bypass
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        c.execute(query)
        
        user = c.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1],
                    "role": user[4]
                }
            }), 200
        else:
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# 2. XSS VULNERABILITIES
# ============================================

@app.route('/api/search', methods=['GET'])
def search():
    """VULNERABLE: Reflected XSS"""
    query = request.args.get('q', '')
    
    # Sin sanitización del input
    html_response = f"""
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {query}</p>
            <p>No results found.</p>
        </body>
    </html>
    """
    
    response = make_response(html_response)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/api/comment', methods=['POST'])
def add_comment():
    """VULNERABLE: Stored XSS potencial"""
    data = request.get_json()
    comment = data.get('comment', '')
    
    # Refleja el comentario sin sanitizar
    return jsonify({
        "success": True,
        "message": "Comment added",
        "your_comment": comment  # Sin encoding
    }), 200

# ============================================
# 3. COMMAND INJECTION VULNERABILITIES
# ============================================

@app.route('/api/ping', methods=['GET'])
def ping_host():
    """VULNERABLE: Command Injection en comando ping"""
    host = request.args.get('host', '127.0.0.1')
    
    try:
        # VULNERABLE: Ejecución directa sin validación
        if os.name == 'nt':  # Windows
            command = f'ping -n 1 {host}'
        else:  # Linux/Mac
            command = f'ping -c 1 {host}'
        
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        
        return jsonify({
            "success": True,
            "host": host,
            "output": output.decode('utf-8', errors='ignore')
        }), 200
        
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/dns', methods=['GET'])
def dns_lookup():
    """VULNERABLE: Command Injection en nslookup"""
    domain = request.args.get('domain', 'example.com')
    
    try:
        # VULNERABLE: Sin sanitización
        if os.name == 'nt':
            command = f'nslookup {domain}'
        else:
            command = f'host {domain}'
        
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        
        return jsonify({
            "success": True,
            "domain": domain,
            "output": output.decode('utf-8', errors='ignore')
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# 4. PATH TRAVERSAL VULNERABILITIES
# ============================================

@app.route('/api/files', methods=['GET'])
def list_files():
    """VULNERABLE: Path Traversal"""
    path = request.args.get('path', '.')
    
    try:
        # VULNERABLE: Sin validación de path
        full_path = os.path.join(os.getcwd(), path)
        
        if os.path.exists(full_path):
            if os.path.isfile(full_path):
                with open(full_path, 'r', errors='ignore') as f:
                    content = f.read()
                return jsonify({
                    "type": "file",
                    "path": path,
                    "content": content
                }), 200
            elif os.path.isdir(full_path):
                files = os.listdir(full_path)
                return jsonify({
                    "type": "directory",
                    "path": path,
                    "files": files
                }), 200
        else:
            return jsonify({"error": "Path not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/download', methods=['GET'])
def download_file():
    """VULNERABLE: Path Traversal en descarga de archivos"""
    filename = request.args.get('file', '')
    
    try:
        # VULNERABLE: Path traversal
        filepath = os.path.join('files', filename)
        
        if os.path.exists(filepath):
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            
            response = make_response(content)
            response.headers['Content-Type'] = 'application/octet-stream'
            response.headers['Content-Disposition'] = f'attachment; filename={filename}'
            return response
        else:
            return jsonify({"error": "File not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# 5. XXE VULNERABILITY
# ============================================

@app.route('/api/parse-xml', methods=['POST'])
def parse_xml():
    """VULNERABLE: XML External Entity (XXE)"""
    xml_data = request.data.decode('utf-8')
    
    try:
        # VULNERABLE: Parser sin protección XXE
        root = ET.fromstring(xml_data)
        
        result = {
            "tag": root.tag,
            "text": root.text,
            "attributes": root.attrib
        }
        
        return jsonify({
            "success": True,
            "parsed": result
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# 6. SSRF VULNERABILITY
# ============================================

@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    """VULNERABLE: Server-Side Request Forgery (SSRF)"""
    url = request.args.get('url', '')
    
    try:
        import urllib.request
        
        # VULNERABLE: Sin validación de URL
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')
        
        return jsonify({
            "success": True,
            "url": url,
            "content": content[:500]  # Primeros 500 caracteres
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/webhook', methods=['GET'])
def webhook():
    """VULNERABLE: SSRF via webhook callback"""
    callback_url = request.args.get('callback', '')
    
    try:
        import urllib.request
        
        # VULNERABLE: Callback sin validación
        data = '{"event": "test", "timestamp": "' + str(time.time()) + '"}'
        req = urllib.request.Request(callback_url, data=data.encode(), method='POST')
        response = urllib.request.urlopen(req, timeout=5)
        
        return jsonify({
            "success": True,
            "message": "Webhook called",
            "callback": callback_url
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# 7. IDOR VULNERABILITIES
# ============================================

@app.route('/api/documents/<doc_id>', methods=['GET'])
def get_document(doc_id):
    """VULNERABLE: IDOR - Sin verificación de autorización"""
    try:
        conn = sqlite3.connect('vulnapi.db')
        c = conn.cursor()
        
        # VULNERABLE: Sin verificar si el usuario tiene acceso
        c.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
        row = c.fetchone()
        
        if row:
            doc = {
                'id': row[0],
                'title': row[1],
                'content': row[2],
                'owner_id': row[3]
            }
            conn.close()
            return jsonify(doc), 200
        else:
            conn.close()
            return jsonify({"error": "Document not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/profile/<user_id>', methods=['GET'])
def get_profile(user_id):
    """VULNERABLE: IDOR en perfiles de usuario"""
    try:
        conn = sqlite3.connect('vulnapi.db')
        c = conn.cursor()
        
        # VULNERABLE: Acceso sin autenticación
        c.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        
        if row:
            profile = {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3]
            }
            conn.close()
            return jsonify(profile), 200
        else:
            conn.close()
            return jsonify({"error": "Profile not found"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# 8. RATE LIMITING - SIN PROTECCIÓN
# ============================================

@app.route('/api/public/data', methods=['GET'])
def public_data():
    """VULNERABLE: Sin rate limiting"""
    return jsonify({
        "message": "Public data endpoint",
        "data": "This endpoint has no rate limiting protection",
        "timestamp": time.time()
    }), 200

@app.route('/api/sensitive', methods=['GET'])
def sensitive_endpoint():
    """VULNERABLE: Endpoint sensible sin rate limiting"""
    return jsonify({
        "sensitive_data": "API_KEY_12345_SECRET",
        "internal_info": "Database: db.internal.local:5432"
    }), 200

# ============================================
# INFORMACIÓN Y ENDPOINTS DE AYUDA
# ============================================

@app.route('/api/vulnerabilities', methods=['GET'])
def list_vulnerabilities():
    """Lista todas las vulnerabilidades implementadas"""
    return jsonify({
        "vulnerabilities": {
            "sql_injection": {
                "count": 3,
                "endpoints": [
                    "/api/users/search?username=admin",
                    "/api/users/1",
                    "/api/login"
                ],
                "example_payload": "' OR '1'='1' --"
            },
            "xss": {
                "count": 2,
                "endpoints": [
                    "/api/search?q=<script>alert('XSS')</script>",
                    "/api/comment"
                ],
                "example_payload": "<script>alert('XSS')</script>"
            },
            "command_injection": {
                "count": 2,
                "endpoints": [
                    "/api/ping?host=127.0.0.1",
                    "/api/dns?domain=example.com"
                ],
                "example_payload": "; cat /etc/passwd"
            },
            "path_traversal": {
                "count": 2,
                "endpoints": [
                    "/api/files?path=.",
                    "/api/download?file=test.txt"
                ],
                "example_payload": "../../../etc/passwd"
            },
            "xxe": {
                "count": 1,
                "endpoints": ["/api/parse-xml"],
                "example_payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
            },
            "ssrf": {
                "count": 2,
                "endpoints": [
                    "/api/fetch?url=http://example.com",
                    "/api/webhook?callback=http://example.com"
                ],
                "example_payload": "http://169.254.169.254/latest/meta-data/"
            },
            "idor": {
                "count": 2,
                "endpoints": [
                    "/api/documents/1",
                    "/api/profile/1"
                ],
                "description": "Prueba IDs del 1 al 100"
            },
            "rate_limiting": {
                "count": 2,
                "endpoints": [
                    "/api/public/data",
                    "/api/sensitive"
                ],
                "description": "Sin límite de requests"
            }
        }
    }), 200

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "database": "connected",
        "timestamp": time.time()
    }), 200

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                         VulnAPI                               ║
║              API Vulnerable para Práctica                     ║
╚═══════════════════════════════════════════════════════════════╝

[!] ADVERTENCIA: Esta API contiene vulnerabilidades INTENCIONADAS
[!] SOLO para uso en entorno de pruebas/laboratorio

Inicializando base de datos...
    """)
    
    init_db()
    
    print("""
✓ Base de datos inicializada
✓ Usuarios de prueba creados
✓ Documentos de prueba creados

API corriendo en: http://localhost:5000

Endpoints disponibles:
- http://localhost:5000/                    (Información general)
- http://localhost:5000/api/vulnerabilities (Lista de vulnerabilidades)

Usuarios de prueba:
- admin / admin123
- user1 / password1
- testuser / test123

¡Listo para fuzzing!
    """)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
