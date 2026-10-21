#!/usr/bin/env bash
# T7 — Certificado de cliente (autenticação mútua)
# Antes: completar a seção [v3_cliente] de openssl/intermediaria.cnf
source "$(dirname "$0")/_comum.sh"
I="$PKI_DIR/inter"
C=saida/clientes
mkdir -p "$C"

# TODO: chave (P-256) em $C/aluno.key, CSR com titular "/C=BR/O=$ORG/CN=$MATRICULA"
#       e certificado $C/aluno.crt emitido pela intermediária (extensões v3_cliente, 365 dias)

# TODO: saida/web/acs-confiaveis.pem = certificado da raiz seguido do certificado da intermediária

openssl verify -CAfile "$PKI_DIR/raiz/raiz.crt" -untrusted "$I/inter.crt" -purpose sslclient "$C/aluno.crt"
