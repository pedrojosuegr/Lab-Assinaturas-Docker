#!/usr/bin/env bash
# T8 — Revogação e Lista de Certificados Revogados (LCR)
source "$(dirname "$0")/_comum.sh"
I="$PKI_DIR/inter"
C=saida/clientes

# 1) TODO: emitir um segundo certificado de cliente, $C/revogado.crt (chave $C/revogado.key),
#          titular "/C=BR/O=$ORG/CN=$MATRICULA-revogado", extensões v3_cliente

# 2) TODO: revogar $C/revogado.crt com o motivo keyCompromise
#          openssl ca -config ... -revoke ... -crl_reason keyCompromise

# 3) TODO: gerar a LCR da intermediária ($I/inter.crl) e a da raiz ($PKI_DIR/raiz/raiz.crl)
#          com "openssl ca -config ... -gencrl -out ..."

# 4) TODO: saida/web/crl.pem = LCR da raiz seguida da LCR da intermediária

openssl crl -in "$I/inter.crl" -noout -text | grep -A3 "Revoked Certificates"
