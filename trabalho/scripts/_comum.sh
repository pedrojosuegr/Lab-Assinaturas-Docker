# Trecho comum a todos os scripts (carregado com "source"). Não é necessário alterar.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."           # pasta "trabalho"
. ./aluno.env
if [ -z "${MATRICULA}" ]; then
    echo "Preencher MATRICULA no arquivo aluno.env antes de continuar." >&2
    exit 1
fi
export PKI_DIR="$PWD/saida/pki"                    # usado pelos arquivos openssl/*.cnf
MAT="../materiais"                                 # materiais fornecidos pelo professor
ORG="PUC Goias - Lab Cripto"

# Prepara a pasta de uma AC para o comando "openssl ca"
preparar_ac() {
    mkdir -p "$1/emitidos"
    [ -f "$1/index.txt" ] || : > "$1/index.txt"
    [ -f "$1/serial" ]    || openssl rand -hex 8 > "$1/serial"
    [ -f "$1/crlnumber" ] || echo 1000 > "$1/crlnumber"
}
