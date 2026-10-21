#!/usr/bin/env bash
# T1 — Assinar um arquivo com RSA-PSS e com ECDSA (P-256)
source "$(dirname "$0")/_comum.sh"
D=saida/t1
mkdir -p "$D"
ARQ="$MAT/t1/relatorio.txt"

# (a) Chave RSA de 3072 bits em $D/rsa.key e chave pública em $D/rsa.pub
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$D/rsa.key"     # pronto (modelo)
# TODO: extrair a chave pública para $D/rsa.pub
openssl pkey -in "$D/rsa.key" -pubout -out "$D/rsa.pub"

# (b) Assinatura RSA-PSS com SHA-256 do arquivo $ARQ, gravada em $D/relatorio.rsa.sig
# TODO
openssl dgst -sha256 -sign "$D/rsa.key" \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest \
  -out "$D/relatorio.rsa.sig" "$ARQ"

# (c) Chave ECDSA na curva P-256 ($D/ec.key e $D/ec.pub) e assinatura SHA-256 em $D/relatorio.ec.sig
# TODO
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$D/ec.key"
openssl pkey -in "$D/ec.key" -pubout -out "$D/ec.pub"
openssl dgst -sha256 -sign "$D/ec.key" -out "$D/relatorio.ec.sig" "$ARQ"

# (d) Verificar as duas assinaturas com as chaves públicas (deve aparecer "Verified OK" duas vezes)
# TODO
openssl dgst -sha256 -verify "$D/rsa.pub" \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest \
  -signature "$D/relatorio.rsa.sig" "$ARQ"

openssl dgst -sha256 -verify "$D/ec.pub" \
  -signature "$D/relatorio.ec.sig" "$ARQ"

ls -l "$D"