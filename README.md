# Laboratório — Assinaturas Digitais e Certificados com Docker

**Criptografia Aplicada — PUC Goiás — Escola Politécnica**
Módulo 5 — Hash e Assinatura Digital (continuação do notebook *Assinaturas Digitais*)

---

## Objetivos

Ao final do laboratório, espera-se que seja possível:

1. assinar e verificar arquivos com RSA-PSS e ECDSA usando o OpenSSL;
2. automatizar a verificação de assinaturas de pacotes de software;
3. construir uma Infraestrutura de Chaves Públicas de dois níveis (AC Raiz e AC Intermediária);
4. emitir certificados de servidor e de cliente com as extensões X.509 corretas;
5. publicar um site HTTPS e exigir autenticação mútua (mTLS) no nginx;
6. revogar um certificado e fazer o servidor respeitar a Lista de Certificados Revogados;
7. produzir um documento assinado no formato CMS (`.p7s`), o mesmo usado nas assinaturas ICP-Brasil.

## Organização

| Parte | Conteúdo |
|---|---|
| Parte I | Conceitos necessários: Docker, OpenSSL, ICP de dois níveis, extensões X.509, TLS e mTLS, LCR, CMS |
| Parte II | Preparação do ambiente |
| Parte III | Tarefas T1 a T9, todas práticas, com correção automática |

---

# Parte I — Conceitos

## 1. O ambiente: Docker e Docker Compose

> **Sigla — Docker.** Plataforma que executa aplicações em **contêineres**: processos isolados que trazem consigo as próprias bibliotecas e ferramentas. Um contêiner é criado a partir de uma **imagem** (um modelo somente leitura). O **Docker Compose** descreve, em um único arquivo (`docker-compose.yml`), vários contêineres que trabalham juntos, as redes que os ligam e as pastas compartilhadas com o computador (*volumes*).

O laboratório utiliza três serviços:

| Serviço | Imagem | Função |
|---|---|---|
| `ferramentas` | construída a partir de `imagem/Dockerfile` (Debian + OpenSSL + curl + Python) | terminal de trabalho, onde os scripts são executados |
| `web` | `nginx:1.27-alpine` | servidor HTTPS com o nome `web.lab.local` |
| `corretor` | a mesma imagem de `ferramentas` | correção automática das tarefas |

```
 Computador (pasta do laboratório)
 ├── trabalho/  ◀──── compartilhada ────▶  /lab/trabalho   (contêineres ferramentas e corretor)
 │   ├── saida/web  ◀── compartilhada ──▶  /etc/nginx/lab   (contêiner web)
 │   └── web/       ◀── compartilhada ──▶  /etc/nginx/conf.d
 └── materiais/ ◀──── somente leitura ─▶  /lab/materiais

 Rede "lab":   ferramentas ───▶ https://web.lab.local ◀─── corretor
```

Tudo o que os scripts gravam em `trabalho/saida` aparece imediatamente no computador e no contêiner do nginx.

## 2. OpenSSL

> **Sigla — OpenSSL.** Biblioteca e ferramenta de linha de comando de código aberto que implementa TLS e a maior parte dos algoritmos criptográficos em uso. O nome vem de SSL (*Secure Sockets Layer*), antecessor do TLS. A ferramenta `openssl` é organizada em subcomandos:

| Subcomando | Uso no laboratório |
|---|---|
| `openssl genpkey` | gerar chaves privadas (RSA, curvas elípticas) |
| `openssl pkey` | converter chaves; extrair a chave pública (`-pubout`) |
| `openssl dgst` | calcular hash e assinar/verificar arquivos (`-sign`, `-verify`) |
| `openssl req` | criar pedidos de certificado (CSR) ou certificados autoassinados (`-x509`) |
| `openssl ca` | operar uma AC: emitir, registrar, revogar e gerar LCR |
| `openssl x509` | exibir e converter certificados |
| `openssl verify` | validar um certificado contra uma cadeia |
| `openssl crl` | exibir uma LCR |
| `openssl cms` | assinar e verificar documentos no formato CMS |

Para consultar as opções de qualquer subcomando: `openssl <subcomando> -help`.

## 3. Uma ICP de dois níveis

> **Sigla — ICP (Infraestrutura de Chaves Públicas; em inglês, PKI).** Conjunto de autoridades, normas e procedimentos que emitem e gerenciam certificados digitais.
>
> **Sigla — AC (Autoridade Certificadora; em inglês, CA).** Entidade que assina certificados. Uma AC **raiz** assina o próprio certificado (autoassinado) e precisa ser instalada previamente como confiável. Uma AC **intermediária** tem o certificado assinado por outra AC.
>
> **Sigla — CSR (*Certificate Signing Request*, pedido de assinatura de certificado).** Arquivo que o titular envia à AC contendo o nome desejado e a chave pública, assinado com a chave privada correspondente (o que prova que o solicitante possui essa chave). A chave privada nunca sai do solicitante.

```
   AC Raiz Lab <matrícula>            chave P-384, 10 anos, autoassinada       (T3)
          │ assina
          ▼
   AC Intermediaria Lab <matrícula>   chave P-256, 5 anos, pathlen:0           (T4)
          │ assina
          ├──────────────────────────┬──────────────────────────┐
          ▼                          ▼                          ▼
   web.lab.local (servidor)   <matrícula> (cliente)   <matrícula>-revogado     (T5, T7, T8)
```

A chave da raiz é usada raramente (apenas para assinar intermediárias e a própria LCR). No mundo real, ela fica fora de rede, em um módulo de *hardware* criptográfico; se a intermediária for comprometida, a raiz a revoga sem que seja necessário reinstalar a raiz em todos os computadores. A ICP-Brasil segue essa mesma estrutura: AC Raiz (ITI) → ACs de primeiro e segundo nível → titulares.

**Como o `openssl ca` funciona.** Cada AC tem uma pasta (`saida/pki/raiz` e `saida/pki/inter`) com:

| Arquivo | Conteúdo |
|---|---|
| `index.txt` | banco de dados: uma linha por certificado emitido, com `V` (válido) ou `R` (revogado) |
| `serial` | próximo número de série, em hexadecimal |
| `crlnumber` | próximo número de LCR |
| `emitidos/` | cópia de cada certificado emitido |

Essas pastas são preparadas pela função `preparar_ac`, já pronta em `scripts/_comum.sh`. As regras de cada AC estão nos arquivos `trabalho/openssl/raiz.cnf` e `trabalho/openssl/intermediaria.cnf`.

## 4. Extensões X.509 v3

> **Sigla — X.509.** Norma da ITU-T que define o formato dos certificados. A versão 3 (v3) introduziu as **extensões**, campos adicionais que restringem o uso do certificado. Uma extensão marcada como **crítica** (*critical*) deve ser compreendida e respeitada por quem valida; se não for reconhecida, o certificado deve ser rejeitado.

| Extensão | Valores usados | Significado |
|---|---|---|
| `basicConstraints` | `CA:TRUE` ou `CA:FALSE`; `pathlen:N` | se o titular pode emitir certificados; `pathlen:0` impede que uma AC crie outras ACs abaixo dela |
| `keyUsage` | `keyCertSign`, `cRLSign`, `digitalSignature`, `nonRepudiation` | operações permitidas à chave. `keyCertSign`: assinar certificados; `cRLSign`: assinar LCRs; `digitalSignature`: assinaturas em geral (inclusive no TLS); `nonRepudiation` (também chamado *contentCommitment*): assinaturas de documentos com valor de compromisso |
| `extendedKeyUsage` (EKU) | `serverAuth`, `clientAuth`, `emailProtection` | finalidades específicas: servidor TLS, cliente TLS, assinatura/cifragem de mensagens (S/MIME e CMS) |
| `subjectAltName` (SAN) | `DNS:web.lab.local` | nomes válidos para o titular. **Navegadores e bibliotecas atuais conferem o nome do servidor apenas no SAN**, não no CN |
| `subjectKeyIdentifier` (SKI) / `authorityKeyIdentifier` (AKI) | `hash` / `keyid:always` | identificadores da chave do titular e da chave do emissor; permitem montar a cadeia mesmo quando há várias chaves com o mesmo nome |

Sintaxe nos arquivos `.cnf` (exemplo genérico):

```
[ nome_da_secao ]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature
```

> **Sigla — CN (*Common Name*, nome comum).** Campo do nome do titular, como em `/C=BR/O=Organização/CN=Nome`. **C** = país (*Country*); **O** = organização (*Organization*).

## 5. TLS, HTTPS e autenticação mútua

> **Sigla — TLS (*Transport Layer Security*).** Protocolo que protege conexões na internet. O **HTTPS** é o HTTP transportado sobre TLS.
>
> **Sigla — mTLS (*mutual TLS*, TLS mútuo).** Variante em que, além do servidor, **o cliente também apresenta um certificado**. É usada em APIs entre empresas, em sistemas bancários (Open Finance) e em serviços públicos, como o envio de NF-e com e-CNPJ.

No início de cada conexão TLS (*handshake*):

1. o servidor envia a **cadeia**: o próprio certificado e o da intermediária (não envia a raiz, que o cliente já deve ter);
2. o cliente valida a cadeia até uma raiz confiável e confere se `web.lab.local` aparece no SAN;
3. o servidor **assina** os dados da negociação com a chave privada dele, provando que possui a chave do certificado;
4. no mTLS, o servidor pede um certificado ao cliente, que repete os passos 1 a 3 no sentido oposto.

> **Atenção.** Se o servidor enviar apenas o próprio certificado, sem a intermediária, um cliente que conhece só a raiz não consegue montar a cadeia e recusa a conexão (`unable to get local issuer certificate`). Esse é um dos erros de configuração mais frequentes em servidores reais.

## 6. Revogação

> **Sigla — LCR (Lista de Certificados Revogados; em inglês, CRL, *Certificate Revocation List*).** Lista, assinada pela AC, com os números de série dos certificados cancelados antes do vencimento (chave vazada, mudança de cargo, dados incorretos). Cada AC publica a própria LCR, com data de validade.
>
> **Sigla — OCSP (*Online Certificate Status Protocol*).** Alternativa à LCR: consulta *on-line* ao servidor da AC sobre um único certificado. Não é usado neste laboratório.

O nginx, ao validar certificados de cliente com `ssl_crl`, exige uma LCR **para cada AC da cadeia** (raiz e intermediária). Se faltar uma delas, todos os clientes passam a ser recusados.

## 7. CMS: o envelope das assinaturas de documentos

> **Sigla — CMS (*Cryptographic Message Syntax*).** Formato padronizado (RFC 5652, derivado do **PKCS#7**) que empacota: a assinatura, o algoritmo de hash, a data e o certificado do assinante (e, opcionalmente, os das ACs intermediárias). A extensão de arquivo usual é **`.p7s`**.
>
> **Sigla — CAdES (*CMS Advanced Electronic Signatures*).** Perfil do CMS adotado pela ICP-Brasil para assinaturas de documentos. Os arquivos `.p7s` gerados pelos assinadores de e-CPF seguem esse formato.

Uma assinatura CMS pode ser:

- **destacada** (*detached*): o `.p7s` contém só a assinatura; o documento original é distribuído junto, como arquivo separado;
- **anexada** (*attached*): o `.p7s` contém também o documento.

Para validar, o verificador precisa conhecer apenas a raiz: as intermediárias viajam dentro do próprio `.p7s`.

---

# Parte II — Preparação do ambiente

**Requisitos:** Docker Desktop (Windows ou macOS) ou Docker Engine com o plugin Compose (Linux). Na primeira execução, é necessário acesso à internet para baixar as imagens.

1. Descompactar o laboratório e abrir um terminal na pasta `lab-assinaturas-docker`.
2. Preencher `trabalho/aluno.env` com matrícula e nome.
3. Construir a imagem e subir o contêiner de ferramentas:

   ```
   docker compose up -d --build
   ```

4. Abrir um terminal dentro do contêiner:

   ```
   docker compose exec ferramentas bash
   ```

   O terminal abre em `/lab/trabalho`. **Todos os scripts são executados ali**, com `bash scripts/<nome>.sh`.

**Comandos úteis (no computador, fora do contêiner)**

| Ação | Comando |
|---|---|
| Subir o servidor HTTPS (a partir da T6) | `docker compose up -d web` |
| Recarregar o nginx após alterar certificados ou `lab.conf` | `docker compose restart web` |
| Ver erros do nginx | `docker compose logs web` |
| Executar a correção | `docker compose run --rm corretor` |
| Encerrar tudo | `docker compose down` |

**Observações**

- Os arquivos podem ser editados no computador, com qualquer editor; as alterações aparecem no contêiner na hora. No Windows, o editor deve salvar com fim de linha **LF** (no VS Code: canto inferior direito, "CRLF" → "LF"). Se um script falhar com `$'\r': command not found`, executar no contêiner: `dos2unix scripts/*.sh`.
- Para recomeçar do zero: `bash scripts/limpar.sh` (apaga a pasta `saida`).
- Cada script pode ser executado novamente após correções. Ao refazer a raiz (T3), refazer também as tarefas seguintes, pois todos os certificados dependem dela.

---

# Parte III — Tarefas

**Atividade avaliativa.** Todas as tarefas são práticas e verificadas pelo corretor automático. Os pesos estão em porcentagem da nota da atividade.

| Tarefa | Tema | Peso |
|---|---|---|
| T1 | Assinatura de arquivo com RSA-PSS e ECDSA | 10% |
| T2 | Verificação automatizada de um lote de atualizações | 10% |
| T3 | AC Raiz | 12% |
| T4 | AC Intermediária | 12% |
| T5 | Certificado do servidor | 14% |
| T6 | HTTPS no nginx | 12% |
| T7 | Autenticação mútua (mTLS) | 10% |
| T8 | Revogação e LCR | 10% |
| T9 | Documento assinado em CMS (`.p7s`) | 10% |
| **Total** | | **100%** |

**Critério:** uma tarefa é considerada concluída quando o corretor exibe `[OK]` para ela. O corretor não confere apenas a existência dos arquivos: ele valida assinaturas, extensões, cadeias e o comportamento do servidor, e executa o script da T2 em um lote novo, gerado no momento da correção.

**Entrega:** a pasta `trabalho` compactada (`.zip`), contendo `saida/resultado_correcao.txt`, conforme orientação do professor. **Atenção:** a pasta contém chaves privadas; em um sistema real, elas jamais seriam entregues a terceiros. Aqui, servem apenas para a correção.

---

## T1 — Assinatura de arquivo com RSA-PSS e ECDSA (10%)

**Arquivo:** `scripts/t1_assinar.sh`  •  **Entrada:** `../materiais/t1/relatorio.txt`

Completar o script para:

1. gerar uma chave RSA de 3072 bits (`saida/t1/rsa.key`) e a chave pública correspondente (`saida/t1/rsa.pub`);
2. assinar `relatorio.txt` com **RSA-PSS** e SHA-256 (`saida/t1/relatorio.rsa.sig`);
3. gerar uma chave ECDSA na curva **P-256** (`saida/t1/ec.key` e `saida/t1/ec.pub`) e assinar o mesmo arquivo com SHA-256 (`saida/t1/relatorio.ec.sig`);
4. verificar as duas assinaturas com as chaves públicas.

**Dicas**

- Extrair a chave pública: `openssl pkey -in <privada> -pubout -out <publica>`.
- Assinar: `openssl dgst -sha256 -sign <privada> -out <assinatura> <arquivo>`.
- Para usar PSS, acrescentar ao comando de assinatura **e** ao de verificação: `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest`. Sem essas opções, o OpenSSL usa o preenchimento PKCS#1 v1.5, e o corretor rejeita.
- Verificar: `openssl dgst -sha256 -verify <publica> -signature <assinatura> <arquivo>` (deve imprimir `Verified OK`).
- Chave EC: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ...`.
- Comparar os tamanhos: `ls -l saida/t1`. A assinatura RSA-3072 ocupa 384 bytes; a ECDSA, cerca de 71.

---

## T2 — Verificação automatizada de um lote de atualizações (10%)

Um fabricante distribui atualizações de *firmware* em arquivos `.bin`, cada um acompanhado de uma assinatura ECDSA (`.bin.sig`, SHA-256). O servidor de distribuição foi invadido e o lote em `../materiais/t2/pacotes` mistura pacotes legítimos com problemas de vários tipos: assinatura feita com outra chave, conteúdo alterado após a assinatura, assinatura ausente, assinatura corrompida e assinatura de outro pacote.

**Arquivo:** `scripts/t2_verificar_lote.sh`

O script recebe dois argumentos, a pasta dos pacotes e a chave pública do fabricante, e deve imprimir **somente** o nome de cada pacote autêntico, um por linha, em ordem alfabética.

Após completar o script, gerar o resultado do lote fornecido:

```
mkdir -p saida/t2
bash scripts/t2_verificar_lote.sh ../materiais/t2/pacotes ../materiais/t2/fabricante.pub > saida/t2/autenticos.txt
cat saida/t2/autenticos.txt
```

**Dicas**

- `[ -f "$arquivo" ] || continue` passa ao próximo item do laço quando o arquivo não existe.
- O comando `openssl dgst -verify` termina com código 0 quando a assinatura é válida e diferente de 0 caso contrário. Por isso, pode ser usado diretamente em um `if`.
- Não confiar no nome do arquivo nem na existência da assinatura: somente a verificação criptográfica decide.

---

## T3 — AC Raiz (12%)

**Arquivos:** seção `[v3_ac_raiz]` de `openssl/raiz.cnf` e `scripts/t3_ac_raiz.sh`

1. Completar a seção `[v3_ac_raiz]`: `basicConstraints` crítica com `CA:TRUE`; `keyUsage` crítica com `keyCertSign` e `cRLSign`.
2. Completar o script para gerar a chave da raiz na curva **P-384** (`saida/pki/raiz/raiz.key`) e o certificado **autoassinado** `saida/pki/raiz/raiz.crt`, com SHA-384, 3650 dias e titular `/C=BR/O=$ORG/CN=AC Raiz Lab $MATRICULA`.

**Dicas**

- `openssl req -new -x509 -config openssl/raiz.cnf -extensions v3_ac_raiz -key <chave> -sha384 -days 3650 -subj "<titular>" -out <certificado>`.
- Usar aspas duplas em `-subj`, para que `$ORG` e `$MATRICULA` sejam substituídos.
- Conferir o resultado: `openssl x509 -in saida/pki/raiz/raiz.crt -noout -text`. Em um certificado autoassinado, *Issuer* e *Subject* são iguais.

---

## T4 — AC Intermediária (12%)

**Arquivos:** seção `[v3_ac_inter]` de `openssl/raiz.cnf` e `scripts/t4_ac_intermediaria.sh`

1. Completar a seção `[v3_ac_inter]`: como na raiz, mas com `pathlen:0` em `basicConstraints`.
2. No script: gerar a chave P-256 (`saida/pki/inter/inter.key`), o CSR (`saida/pki/inter/inter.csr`) com titular `/C=BR/O=$ORG/CN=AC Intermediaria Lab $MATRICULA` e emitir `saida/pki/inter/inter.crt` com a raiz, por 1825 dias.

**Dicas**

- CSR: `openssl req -new -config openssl/intermediaria.cnf -key <chave> -subj "<titular>" -out <csr>`.
- Emissão: `openssl ca -batch -notext -config openssl/raiz.cnf -extensions v3_ac_inter -days 1825 -in <csr> -out <certificado>`.
- Após a emissão, observar a nova linha em `saida/pki/raiz/index.txt`.
- `openssl verify -CAfile saida/pki/raiz/raiz.crt saida/pki/inter/inter.crt` deve imprimir `OK`.

---

## T5 — Certificado do servidor (14%)

**Arquivos:** seção `[v3_servidor]` de `openssl/intermediaria.cnf` e `scripts/t5_servidor.sh`

1. Completar `[v3_servidor]`: `basicConstraints` crítica com `CA:FALSE`; `keyUsage` crítica com `digitalSignature`; `extendedKeyUsage` com `serverAuth`; `subjectAltName` com `DNS:web.lab.local`.
2. No script: chave P-256 em `saida/web/servidor.key`; CSR com titular `/C=BR/O=$ORG/CN=web.lab.local`; certificado `saida/web/servidor.crt` emitido pela **intermediária** por 90 dias.
3. Montar `saida/web/fullchain.pem`: o certificado do servidor seguido do certificado da intermediária (`cat a b > c`).

**Dicas**

- A emissão é igual à da T4, trocando o arquivo de configuração para `openssl/intermediaria.cnf` e a seção para `v3_servidor`.
- Pela decisão SC-081 do CA/Browser Forum, certificados de servidor públicos têm validade máxima de 200 dias desde março de 2026, caindo para 100 dias em 2027 e 47 dias em 2029. Validades curtas reduzem o tempo de uso de uma chave vazada e obrigam a renovação automatizada; 90 dias é a validade usada pelo Let's Encrypt.

---

## T6 — HTTPS no nginx (12%)

**Arquivos:** `scripts/t6_site.sh` e bloco T6 de `web/lab.conf`

1. Completar o script para criar `saida/web/www/index.html` com a matrícula.
2. Em `web/lab.conf`, preencher `ssl_certificate` e `ssl_certificate_key`. No contêiner do nginx, os arquivos de `saida/web` ficam em `/etc/nginx/lab`.
3. No computador: `docker compose up -d web`. Em caso de erro: `docker compose logs web`.
4. Testar a partir do contêiner de ferramentas, confiando **apenas** na raiz do laboratório:

   ```
   curl --cacert saida/pki/raiz/raiz.crt https://web.lab.local/
   openssl s_client -connect web.lab.local:443 -servername web.lab.local -CAfile saida/pki/raiz/raiz.crt -showcerts </dev/null
   ```

**Dicas**

- `ssl_certificate` deve apontar para `fullchain.pem`, não para `servidor.crt`. Vale testar as duas formas e comparar o resultado do `curl`.
- No `openssl s_client`, a linha `Verify return code: 0 (ok)` indica cadeia válida; a seção `Certificate chain` mostra o que o servidor enviou.
- Acessar sem `--cacert` resulta em erro: o sistema não conhece a raiz do laboratório. É a mesma situação de um navegador diante de uma AC não instalada.

---

## T7 — Autenticação mútua (mTLS) (10%)

**Arquivos:** seção `[v3_cliente]` de `openssl/intermediaria.cnf`, `scripts/t7_cliente.sh` e bloco T7 de `web/lab.conf`

1. Completar `[v3_cliente]`: `basicConstraints` crítica com `CA:FALSE`; `keyUsage` crítica com `digitalSignature` e `nonRepudiation`; `extendedKeyUsage` com `clientAuth` e `emailProtection` (a mesma combinação de um e-CPF).
2. No script: emitir `saida/clientes/aluno.crt` (chave `aluno.key`, titular `/C=BR/O=$ORG/CN=$MATRICULA`, 365 dias) e montar `saida/web/acs-confiaveis.pem` com a raiz seguida da intermediária.
3. Em `web/lab.conf`: preencher `ssl_client_certificate`, `ssl_verify_client optional` e `ssl_verify_depth 2`; no `location /restrito`, devolver 403 quando `$ssl_client_verify` for diferente de `SUCCESS`.
4. `docker compose restart web` e testar:

   ```
   curl --cacert saida/pki/raiz/raiz.crt https://web.lab.local/restrito
   curl --cacert saida/pki/raiz/raiz.crt --cert saida/clientes/aluno.crt --key saida/clientes/aluno.key https://web.lab.local/restrito
   ```

**Dicas**

- Sintaxe da condição no nginx: `if ($variavel != VALOR) { return 403 "mensagem\n"; }`.
- O corretor também testa um certificado com o **mesmo nome** do aluno, mas emitido por uma AC desconhecida; ele deve ser recusado. O nome no certificado não prova nada: o que vale é a assinatura da AC.

---

## T8 — Revogação e LCR (10%)

**Arquivos:** `scripts/t8_revogacao.sh` e bloco T8 de `web/lab.conf`

1. Emitir um segundo certificado de cliente, `saida/clientes/revogado.crt` (titular `/C=BR/O=$ORG/CN=$MATRICULA-revogado`).
2. Revogá-lo com o motivo `keyCompromise` e observar a mudança de `V` para `R` em `saida/pki/inter/index.txt`.
3. Gerar a LCR da intermediária (`saida/pki/inter/inter.crl`) e a da raiz (`saida/pki/raiz/raiz.crl`) e juntá-las em `saida/web/crl.pem`.
4. Em `web/lab.conf`, acrescentar `ssl_crl`; `docker compose restart web`.
5. Testar: o certificado revogado deve ser recusado, e o do aluno deve continuar aceito.

**Dicas**

- Revogar: `openssl ca -config openssl/intermediaria.cnf -revoke <certificado> -crl_reason keyCompromise`.
- Gerar LCR: `openssl ca -config <cnf da AC> -gencrl -out <arquivo>`.
- Exibir: `openssl crl -in saida/pki/inter/inter.crl -noout -text`.
- Se o certificado do aluno também passar a ser recusado, falta uma das duas LCRs em `crl.pem` (seção 6 da Parte I).
- A LCR tem validade (30 dias, conforme `default_crl_days`). Vencida, o nginx recusa todos os clientes: em produção, a AC precisa republicá-la periodicamente.

---

## T9 — Documento assinado em CMS (10%)

**Arquivo:** `scripts/t9_cms.sh`  •  **Entrada:** `../materiais/t9/termo.txt`

Assinar `termo.txt` com o certificado e a chave do aluno, gerando `saida/t9/termo.p7s` no formato **DER**, com assinatura **destacada**, SHA-256 e o certificado da intermediária incluído no envelope. O próprio script verifica o resultado usando apenas a raiz.

**Dicas**

- `openssl cms -sign -binary -md sha256 -in <documento> -signer <certificado> -inkey <chave> -certfile <intermediária> -outform DER -out <arquivo.p7s>`.
- O `openssl cms` produz assinatura destacada por padrão; a opção `-nodetach` produziria a versão anexada.
- Inspecionar o envelope: `openssl cms -cmsout -print -inform DER -in saida/t9/termo.p7s | less`. Procurar o algoritmo de hash, a data de assinatura (`signingTime`) e os certificados incluídos.
- O corretor confirma que a assinatura falha quando uma única palavra do termo é alterada.

---

## Correção

No computador, na pasta do laboratório:

```
docker compose run --rm corretor
```

O resultado é exibido na tela e gravado em `trabalho/saida/resultado_correcao.txt`. Para as tarefas T6 a T8, o serviço `web` deve estar no ar.

## Referências

- IETF. *RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile*. 2008.
- IETF. *RFC 5652: Cryptographic Message Syntax (CMS)*. 2009.
- IETF. *RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3*. 2018.
- IETF. *RFC 8017: PKCS #1 — RSA Cryptography Specifications Version 2.2*. 2016.
- NIST. *FIPS 186-5: Digital Signature Standard (DSS)*. 2023.
- ITI. *DOC-ICP-15: Visão geral sobre assinaturas digitais na ICP-Brasil*.
- Documentação do OpenSSL: https://docs.openssl.org
- Documentação do nginx, módulo `ngx_http_ssl_module`: https://nginx.org/en/docs/http/ngx_http_ssl_module.html
- Documentação do Docker Compose: https://docs.docker.com/compose/
