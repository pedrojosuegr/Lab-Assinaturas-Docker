#!/usr/bin/env bash
# T4 — AC Intermediária, emitida pela raiz
# Antes: completar a seção [v3_ac_inter] de openssl/raiz.cnf
source "$(dirname "$0")/_comum.sh"
I="$PKI_DIR/inter"
preparar_ac "$I"

# 1) TODO: chave da intermediária (P-256) em $I/inter.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$I/inter.key"
chmod 600 "$I/inter.key"

# 2) TODO: pedido de certificado (CSR) em $I/inter.csr
#    titular: "/C=BR/O=$ORG/CN=AC Intermediaria Lab $MATRICULA"   (usar -config openssl/intermediaria.cnf)
openssl req -new -config openssl/intermediaria.cnf \
  -key "$I/inter.key" \
  -subj "/C=BR/O=$ORG/CN=AC Intermediaria Lab $MATRICULA" \
  -out "$I/inter.csr"

# 3) TODO: a raiz assina o pedido -> $I/inter.crt
#    openssl ca -batch -notext -config openssl/raiz.cnf -extensions v3_ac_inter -days 1825 -in ... -out ...
openssl ca -batch -notext -config openssl/raiz.cnf -extensions v3_ac_inter -days 1825 \
  -in "$I/inter.csr" -out "$I/inter.crt"

# 4) conferência da cadeia (deve imprimir "OK")
openssl verify -CAfile "$PKI_DIR/raiz/raiz.crt" "$I/inter.crt"
