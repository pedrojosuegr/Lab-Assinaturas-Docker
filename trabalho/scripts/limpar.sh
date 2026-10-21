#!/usr/bin/env bash
# Apaga tudo o que foi gerado em "saida" (chaves, certificados, LCRs), para recomeçar do zero.
cd "$(dirname "$0")/.."
rm -rf saida/*
echo "Pasta saida esvaziada."
