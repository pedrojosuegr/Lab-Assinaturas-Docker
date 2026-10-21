#!/usr/bin/env bash
# T2 — Verificação de um lote de pacotes de atualização
# Uso: bash scripts/t2_verificar_lote.sh PASTA_DOS_PACOTES CHAVE_PUBLICA
# Saída: o nome de cada pacote autêntico (ex.: atualizacao-03.bin), um por linha, em ordem alfabética.
#        Nenhuma outra mensagem deve ser impressa.
set -u
PASTA="$1"
PUB="$2"

for pacote in "$PASTA"/*.bin; do
    assinatura="$pacote.sig"
    # TODO: se o arquivo de assinatura não existir, passar ao próximo pacote
    [ -f "$assinatura" ] || continue

    # TODO: verificar a assinatura com a chave pública; se for válida, imprimir: basename "$pacote"
    #       (descartar as mensagens do openssl com  >/dev/null 2>&1)
    if openssl dgst -sha256 -verify "$PUB" -signature "$assinatura" "$pacote" >/dev/null 2>&1; then
        basename "$pacote"
    fi
done | sort