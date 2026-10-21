#!/usr/bin/env bash
# T3 — AC Raiz autoassinada
# Antes: completar a seção [v3_ac_raiz] de openssl/raiz.cnf
source "$(dirname "$0")/_comum.sh"
R="$PKI_DIR/raiz"
preparar_ac "$R"

# TODO: chave privada da raiz, curva P-384, em $R/raiz.key (e chmod 600)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$R/raiz.key"
chmod 600 "$R/raiz.key"

# TODO: certificado autoassinado em $R/raiz.crt
#   - openssl req -new -x509 -config openssl/raiz.cnf -extensions v3_ac_raiz ...
#   - hash SHA-384, validade de 3650 dias
#   - titular: "/C=BR/O=$ORG/CN=AC Raiz Lab $MATRICULA"
openssl req -new -x509 -config openssl/raiz.cnf -extensions v3_ac_raiz \
  -key "$R/raiz.key" -sha384 -days 3650 \
  -subj "/C=BR/O=$ORG/CN=AC Raiz Lab $MATRICULA" \
  -out "$R/raiz.crt"

openssl x509 -in "$R/raiz.crt" -noout -subject -issuer -dates -ext basicConstraints,keyUsage