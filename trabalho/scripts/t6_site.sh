#!/usr/bin/env bash
# T6 — Página publicada pelo servidor HTTPS
source "$(dirname "$0")/_comum.sh"
mkdir -p saida/web/www

# Página inicial com a matrícula do aluno
cat > saida/web/www/index.html <<EOF
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Laboratório de Assinaturas Digitais</title>
</head>
<body>
  <h1>Laboratório de Criptografia Aplicada</h1>
  <p>Servidor HTTPS: web.lab.local</p>
  <p>Matrícula: $MATRICULA</p>
  <p>Aluno: ${NOME:-}</p>
</body>
</html>
EOF

echo "Página criada. Configurar trabalho/web/lab.conf e executar, no computador: docker compose up -d web"
