#!/usr/bin/env bash
# T9 — Assinatura de documento no formato CMS (.p7s), com o certificado de cliente
source "$(dirname "$0")/_comum.sh"
I="$PKI_DIR/inter"
D=saida/t9
mkdir -p "$D"

# TODO: assinar $MAT/t9/termo.txt -> $D/termo.p7s (assinatura destacada, formato DER, SHA-256)
#       assinante: saida/clientes/aluno.crt e aluno.key
#       incluir o certificado da intermediária no .p7s (-certfile)

# Verificação: só a raiz é informada como confiável; a intermediária deve vir dentro do .p7s
openssl cms -verify -binary -inform DER -in "$D/termo.p7s" \
    -content "$MAT/t9/termo.txt" -CAfile "$PKI_DIR/raiz/raiz.crt" -out /dev/null
