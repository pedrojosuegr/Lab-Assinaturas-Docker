#!/usr/bin/env bash
# T7 — Certificado de cliente (autenticação mútua)
# Antes: completar a seção [v3_cliente] de openssl/intermediaria.cnf
source "$(dirname "$0")/_comum.sh"
I="$PKI_DIR/inter"
C=saida/clientes
mkdir -p "$C" saida/web

# Chave (P-256), CSR e certificado do aluno, emitido pela intermediária (extensões v3_cliente, 365 dias)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$C/aluno.key"
chmod 600 "$C/aluno.key"

openssl req -new -config openssl/intermediaria.cnf \
  -key "$C/aluno.key" \
  -subj "/C=BR/O=$ORG/CN=$MATRICULA" \
  -out "$I/aluno.csr"

openssl ca -batch -notext -config openssl/intermediaria.cnf -extensions v3_cliente -days 365 \
  -in "$I/aluno.csr" -out "$C/aluno.crt"

# ACs aceitas pelo nginx para certificados de cliente: raiz seguida da intermediária
cat "$PKI_DIR/raiz/raiz.crt" "$I/inter.crt" > saida/web/acs-confiaveis.pem

openssl verify -CAfile "$PKI_DIR/raiz/raiz.crt" -untrusted "$I/inter.crt" -purpose sslclient "$C/aluno.crt"
