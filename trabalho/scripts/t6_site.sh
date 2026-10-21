#!/usr/bin/env bash
# T6 — Página publicada pelo servidor HTTPS
source "$(dirname "$0")/_comum.sh"
mkdir -p saida/web/www

# TODO: criar saida/web/www/index.html contendo, no mínimo, a matrícula ($MATRICULA)

echo "Página criada. Configurar trabalho/web/lab.conf e executar, no computador: docker compose up -d web"
