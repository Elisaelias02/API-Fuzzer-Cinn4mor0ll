#!/bin/bash

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║          Test Suite para API  Fuzzer                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

BASE_URL="http://localhost:5000"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[1/9] Testeando SQL Injection...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/users/search --type sql -p username -o reports/sql_injection.txt -v

echo -e "${YELLOW}[2/9] Testeando XSS...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/search --type xss -p q -o reports/xss.txt -v

echo -e "${YELLOW}[3/9] Testeando Command Injection...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/ping --type cmd -p host -o reports/cmd_injection.txt -v

echo -e "${YELLOW}[4/9] Testeando Path Traversal...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/files --type path -p path -o reports/path_traversal.txt -v

echo -e "${YELLOW}[5/9] Testeando XXE...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/parse-xml --type xxe -o reports/xxe.txt -v

echo -e "${YELLOW}[6/9] Testeando SSRF...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/fetch --type ssrf -p url -o reports/ssrf.txt -v

echo -e "${YELLOW}[7/9] Testeando IDOR...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/documents --type idor --id-range 1-10 -o reports/idor.txt -v

echo -e "${YELLOW}[8/9] Testeando Rate Limiting...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL -e /api/public/data --type rate --requests 50 -o reports/rate_limit.txt -v

echo -e "${YELLOW}[9/9] Testeando Security Headers...${NC}"
python3 api_fuzzer_pro.py -u $BASE_URL --type headers -o reports/security_headers.txt -v

echo ""
echo -e "${GREEN}✓ Todos los tests completados!${NC}"
echo -e "Reportes guardados en: ./reports/"
echo ""
echo "Para ver un reporte completo JSON:"
echo "python3 fuzzer.py -u $BASE_URL --type all -j reports/full_audit.json"
