# -*- coding: utf-8 -*-
"""Correção automática do laboratório de Assinaturas Digitais e Certificados.

Execução (no computador, na pasta do laboratório):  docker compose run --rm corretor
O resultado também é gravado em trabalho/saida/resultado_correcao.txt."""
import datetime
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import http.client

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lote import gerar_lote  # noqa: E402

LAB = os.environ.get("LAB_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRAB = os.path.join(LAB, "trabalho")
SAIDA = os.path.join(TRAB, "saida")
MAT = os.path.join(LAB, "materiais")
PKI = os.path.join(SAIDA, "pki")
WEB_HOST = os.environ.get("WEB_HOST", "web.lab.local")
WEB_PORT = int(os.environ.get("WEB_PORT", "443"))

PESOS = {"T1": 10, "T2": 10, "T3": 12, "T4": 12, "T5": 14, "T6": 12, "T7": 10, "T8": 10, "T9": 10}
TITULOS = {
    "T1": "Assinatura de arquivo (RSA-PSS e ECDSA)",
    "T2": "Verificação de lote de atualizações",
    "T3": "AC Raiz",
    "T4": "AC Intermediária",
    "T5": "Certificado do servidor",
    "T6": "HTTPS no nginx",
    "T7": "Autenticação mútua (mTLS)",
    "T8": "Revogação e LCR",
    "T9": "Documento assinado em CMS (.p7s)",
}


class Falha(Exception):
    pass


def exigir(condicao, mensagem):
    if not condicao:
        raise Falha(mensagem)


def ler_env():
    valores = {}
    with open(os.path.join(TRAB, "aluno.env"), encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#") and "=" in linha:
                k, v = linha.split("=", 1)
                valores[k.strip()] = v.strip().strip('"').strip("'")
    return valores


def caminho(*partes):
    p = os.path.join(SAIDA, *partes)
    exigir(os.path.isfile(p), f"arquivo não encontrado: saida/{'/'.join(partes)}")
    return p


def cert(*partes):
    with open(caminho(*partes), "rb") as f:
        dados = f.read()
    try:
        return x509.load_pem_x509_certificate(dados)
    except ValueError:
        raise Falha(f"saida/{'/'.join(partes)} não é um certificado PEM válido")


def chave_privada(*partes):
    with open(caminho(*partes), "rb") as f:
        try:
            return serialization.load_pem_private_key(f.read(), password=None)
        except (ValueError, TypeError):
            raise Falha(f"saida/{'/'.join(partes)} não é uma chave privada PEM sem senha")


def chave_publica(*partes):
    with open(caminho(*partes), "rb") as f:
        try:
            return serialization.load_pem_public_key(f.read())
        except ValueError:
            raise Falha(f"saida/{'/'.join(partes)} não é uma chave pública PEM")


def cn(nome):
    v = nome.get_attributes_for_oid(NameOID.COMMON_NAME)
    return v[0].value if v else None


def ext(c, classe):
    try:
        return c.extensions.get_extension_for_class(classe)
    except x509.ExtensionNotFound:
        return None


def assinado_por(c, emissor_pub):
    try:
        if isinstance(emissor_pub, ec.EllipticCurvePublicKey):
            emissor_pub.verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
        elif isinstance(emissor_pub, rsa.RSAPublicKey):
            emissor_pub.verify(c.signature, c.tbs_certificate_bytes, padding.PKCS1v15(), c.signature_hash_algorithm)
        else:
            emissor_pub.verify(c.signature, c.tbs_certificate_bytes)
        return True
    except InvalidSignature:
        return False


def mesma_chave(pub_a, pub_b):
    f = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub_a.public_bytes(*f) == pub_b.public_bytes(*f)


def dias(c):
    return (c.not_valid_after_utc - c.not_valid_before_utc).total_seconds() / 86400


def openssl(*args):
    r = subprocess.run(["openssl", *args], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def eh_ac(c, pathlen=None):
    bc = ext(c, x509.BasicConstraints)
    exigir(bc is not None, "falta a extensão basicConstraints")
    exigir(bc.critical, "basicConstraints deve ser crítica")
    exigir(bc.value.ca, "basicConstraints deve ter CA:TRUE")
    if pathlen is not None:
        exigir(bc.value.path_length == pathlen, f"basicConstraints deve ter pathlen:{pathlen}")
    ku = ext(c, x509.KeyUsage)
    exigir(ku is not None and ku.critical, "falta keyUsage crítica")
    exigir(ku.value.key_cert_sign and ku.value.crl_sign, "keyUsage deve conter keyCertSign e cRLSign")


def nao_eh_ac(c):
    bc = ext(c, x509.BasicConstraints)
    exigir(bc is not None and bc.critical and not bc.value.ca, "basicConstraints deve ser crítica, com CA:FALSE")


def eku(c):
    e = ext(c, x509.ExtendedKeyUsage)
    return set(e.value) if e else set()


# ------------------------------------------------------------------------- HTTPS
def requisicao(caminho_http, cert_cliente=None, chave_cliente=None):
    """Faz um GET confiando apenas na raiz do aluno. Devolve (status, corpo, certificado do servidor)."""
    ctx = ssl.create_default_context(cafile=os.path.join(PKI, "raiz", "raiz.crt"))
    ctx.check_hostname = True
    if cert_cliente:
        ctx.load_cert_chain(cert_cliente, chave_cliente)
    con = http.client.HTTPSConnection(WEB_HOST, WEB_PORT, context=ctx, timeout=10)
    try:
        con.connect()
        der = con.sock.getpeercert(binary_form=True)
        con.request("GET", caminho_http, headers={"Host": "web.lab.local"})
        resp = con.getresponse()
        corpo = resp.read().decode("utf-8", "replace")
        return resp.status, corpo, x509.load_der_x509_certificate(der)
    finally:
        con.close()


def requisicao_segura(*args, **kwargs):
    try:
        return requisicao(*args, **kwargs)
    except ssl.SSLCertVerificationError as e:
        raise Falha(f"o certificado apresentado pelo servidor não foi aceito: {e.verify_message}")
    except (ConnectionRefusedError, OSError) as e:
        raise Falha(f"não foi possível conectar a https://{WEB_HOST}:{WEB_PORT} ({e}); o serviço web está no ar? "
                    "(docker compose up -d web / docker compose logs web)")


def status_sem_sucesso(*args, **kwargs):
    """Para testes em que o acesso DEVE ser negado: qualquer status diferente de 200, ou recusa no handshake."""
    try:
        status, _, _ = requisicao(*args, **kwargs)
        return status != 200, status
    except ssl.SSLError as e:
        return True, f"handshake recusado ({e.reason})"
    except (ConnectionResetError, BrokenPipeError):
        return True, "conexão encerrada pelo servidor"


# ------------------------------------------------------------------------- tarefas
def t1(mat):
    arq = os.path.join(MAT, "t1", "relatorio.txt")
    with open(arq, "rb") as f:
        dados = f.read()

    priv = chave_privada("t1", "rsa.key")
    exigir(isinstance(priv, rsa.RSAPrivateKey), "rsa.key não é uma chave RSA")
    exigir(priv.key_size == 3072, f"a chave RSA deve ter 3072 bits (tem {priv.key_size})")
    exigir(mesma_chave(priv.public_key(), chave_publica("t1", "rsa.pub")), "rsa.pub não corresponde a rsa.key")
    with open(caminho("t1", "relatorio.rsa.sig"), "rb") as f:
        sig = f.read()
    pub = priv.public_key()
    try:
        pub.verify(sig, dados, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO), hashes.SHA256())
    except InvalidSignature:
        try:
            pub.verify(sig, dados, padding.PKCS1v15(), hashes.SHA256())
            raise Falha("a assinatura RSA usa PKCS#1 v1.5; deve usar PSS (-sigopt rsa_padding_mode:pss)")
        except InvalidSignature:
            raise Falha("a assinatura RSA não confere com relatorio.txt (SHA-256 e PSS)")

    priv_ec = chave_privada("t1", "ec.key")
    exigir(isinstance(priv_ec, ec.EllipticCurvePrivateKey) and priv_ec.curve.name == "secp256r1",
           "ec.key deve ser uma chave ECDSA na curva P-256 (secp256r1)")
    exigir(mesma_chave(priv_ec.public_key(), chave_publica("t1", "ec.pub")), "ec.pub não corresponde a ec.key")
    with open(caminho("t1", "relatorio.ec.sig"), "rb") as f:
        sig_ec = f.read()
    try:
        priv_ec.public_key().verify(sig_ec, dados, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Falha("a assinatura ECDSA não confere com relatorio.txt (SHA-256)")
    return "RSA-3072/PSS e ECDSA P-256 conferidos"


def _rodar_t2(pasta, pub):
    script = os.path.join(TRAB, "scripts", "t2_verificar_lote.sh")
    exigir(os.path.isfile(script), "scripts/t2_verificar_lote.sh não encontrado")
    with open(script, encoding="utf-8") as f:
        codigo = f.read().replace("\r", "")          # tolera arquivos salvos com fim de linha do Windows
    tmp = os.path.join(tempfile.mkdtemp(), "t2.sh")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(codigo)
    r = subprocess.run(["bash", tmp, pasta, pub], capture_output=True, text=True, timeout=120)
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def t2(mat):
    # (a) lote fornecido
    pasta = os.path.join(MAT, "t2")
    esperado = sorted(f for f in os.listdir(os.path.join(pasta, "pacotes"))
                      if f.endswith(".bin") and _valido(os.path.join(pasta, "pacotes", f), os.path.join(pasta, "fabricante.pub")))
    obtido = _rodar_t2(os.path.join(pasta, "pacotes"), os.path.join(pasta, "fabricante.pub"))
    exigir(obtido == esperado, f"lote fornecido: esperado {len(esperado)} pacotes autênticos, o script listou {obtido}")

    arquivo = caminho("t2", "autenticos.txt")
    with open(arquivo, encoding="utf-8") as f:
        gravado = [l.strip() for l in f if l.strip()]
    exigir(gravado == esperado, "saida/t2/autenticos.txt não corresponde à saída correta do script")

    # (b) lote novo, gerado agora com outra chave
    tmp = tempfile.mkdtemp()
    esperado_b = gerar_lote(tmp, quantidade=14)
    obtido_b = _rodar_t2(os.path.join(tmp, "pacotes"), os.path.join(tmp, "fabricante.pub"))
    shutil.rmtree(tmp, ignore_errors=True)
    exigir(obtido_b == esperado_b, "o script falhou em um lote novo, gerado na correção (verificar todos os casos de falha)")
    return f"{len(esperado)} autênticos no lote fornecido; lote novo também correto"


def _valido(arq, pub_pem):
    sig = arq + ".sig"
    if not os.path.isfile(sig):
        return False
    with open(pub_pem, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    try:
        with open(arq, "rb") as a, open(sig, "rb") as s:
            pub.verify(s.read(), a.read(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def t3(mat):
    c = cert("pki", "raiz", "raiz.crt")
    k = chave_privada("pki", "raiz", "raiz.key")
    exigir(cn(c.subject) == f"AC Raiz Lab {mat}", f"CN da raiz deve ser 'AC Raiz Lab {mat}' (encontrado: {cn(c.subject)!r})")
    exigir(c.subject == c.issuer, "a raiz deve ser autoassinada (emissor = titular)")
    exigir(isinstance(k, ec.EllipticCurvePrivateKey) and k.curve.name == "secp384r1", "a chave da raiz deve ser P-384")
    exigir(mesma_chave(k.public_key(), c.public_key()), "raiz.key não corresponde a raiz.crt")
    exigir(assinado_por(c, c.public_key()), "a assinatura do certificado raiz não confere com a própria chave")
    exigir(isinstance(c.signature_hash_algorithm, hashes.SHA384), "a raiz deve ser assinada com SHA-384")
    eh_ac(c)
    exigir(ext(c, x509.SubjectKeyIdentifier) is not None, "falta subjectKeyIdentifier")
    exigir(dias(c) >= 3649, f"validade da raiz deve ser de 3650 dias (tem {dias(c):.0f})")
    return "raiz P-384, autoassinada, CA:TRUE, keyCertSign/cRLSign"


def t4(mat):
    raiz = cert("pki", "raiz", "raiz.crt")
    c = cert("pki", "inter", "inter.crt")
    k = chave_privada("pki", "inter", "inter.key")
    exigir(cn(c.subject) == f"AC Intermediaria Lab {mat}", f"CN da intermediária deve ser 'AC Intermediaria Lab {mat}'")
    exigir(c.issuer == raiz.subject, "o emissor da intermediária deve ser a raiz")
    exigir(assinado_por(c, raiz.public_key()), "a intermediária não foi assinada pela chave da raiz")
    exigir(isinstance(k, ec.EllipticCurvePrivateKey) and k.curve.name == "secp256r1", "a chave da intermediária deve ser P-256")
    exigir(mesma_chave(k.public_key(), c.public_key()), "inter.key não corresponde a inter.crt")
    eh_ac(c, pathlen=0)
    aki = ext(c, x509.AuthorityKeyIdentifier)
    ski = ext(raiz, x509.SubjectKeyIdentifier)
    exigir(aki is not None and ski is not None and aki.value.key_identifier == ski.value.digest,
           "authorityKeyIdentifier da intermediária deve apontar para a chave da raiz")
    exigir(c.not_valid_after_utc <= raiz.not_valid_after_utc, "a intermediária não pode vencer depois da raiz")
    ok, msg = openssl("verify", "-CAfile", caminho("pki", "raiz", "raiz.crt"), caminho("pki", "inter", "inter.crt"))
    exigir(ok, f"openssl verify falhou: {msg}")
    return "intermediária P-256, CA:TRUE, pathlen:0, assinada pela raiz"


def t5(mat):
    inter = cert("pki", "inter", "inter.crt")
    c = cert("web", "servidor.crt")
    k = chave_privada("web", "servidor.key")
    exigir(c.issuer == inter.subject and assinado_por(c, inter.public_key()), "o servidor deve ser emitido pela intermediária")
    exigir(mesma_chave(k.public_key(), c.public_key()), "servidor.key não corresponde a servidor.crt")
    nao_eh_ac(c)
    san = ext(c, x509.SubjectAlternativeName)
    exigir(san is not None and "web.lab.local" in san.value.get_values_for_type(x509.DNSName),
           "subjectAltName deve conter DNS:web.lab.local")
    exigir(ExtendedKeyUsageOID.SERVER_AUTH in eku(c), "extendedKeyUsage deve conter serverAuth")
    ku = ext(c, x509.KeyUsage)
    exigir(ku is not None and ku.value.digital_signature, "keyUsage deve conter digitalSignature")
    exigir(dias(c) <= 91, f"validade do servidor deve ser de no máximo 90 dias (tem {dias(c):.0f})")

    with open(caminho("web", "fullchain.pem"), "rb") as f:
        cadeia = x509.load_pem_x509_certificates(f.read())
    exigir(len(cadeia) == 2 and cadeia[0] == c and cadeia[1] == inter,
           "fullchain.pem deve conter, nesta ordem, o certificado do servidor e o da intermediária")
    ok, msg = openssl("verify", "-CAfile", caminho("pki", "raiz", "raiz.crt"), "-untrusted", caminho("pki", "inter", "inter.crt"),
                      "-purpose", "sslserver", caminho("web", "servidor.crt"))
    exigir(ok, f"openssl verify falhou: {msg}")
    return "servidor web.lab.local, serverAuth, 90 dias, cadeia completa"


def t6(mat):
    caminho("web", "www", "index.html")
    status, corpo, apresentado = requisicao_segura("/")
    exigir(status == 200, f"GET / devolveu {status}")
    exigir(mat in corpo, "a página inicial deve conter a matrícula")
    exigir(apresentado == cert("web", "servidor.crt"), "o nginx não está apresentando saida/web/servidor.crt")
    return "https://web.lab.local/ aceito com a raiz do aluno"


def t7(mat):
    c = cert("clientes", "aluno.crt")
    inter = cert("pki", "inter", "inter.crt")
    exigir(c.issuer == inter.subject and assinado_por(c, inter.public_key()), "aluno.crt deve ser emitido pela intermediária")
    exigir(cn(c.subject) == mat, f"o CN do certificado de cliente deve ser a matrícula ({mat})")
    nao_eh_ac(c)
    exigir({ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION} <= eku(c),
           "extendedKeyUsage deve conter clientAuth e emailProtection")
    ku = ext(c, x509.KeyUsage)
    exigir(ku is not None and ku.value.digital_signature and ku.value.content_commitment,
           "keyUsage deve conter digitalSignature e nonRepudiation")

    crt, key = caminho("clientes", "aluno.crt"), caminho("clientes", "aluno.key")
    status, corpo, _ = requisicao_segura("/restrito", crt, key)
    exigir(status == 200 and mat in corpo, f"com o certificado do aluno, /restrito devolveu {status}")

    negado, st = status_sem_sucesso("/restrito")
    exigir(negado, "sem certificado de cliente, /restrito não pode devolver 200")

    # certificado com o mesmo nome, emitido por uma AC desconhecida
    tmp = tempfile.mkdtemp()
    ac = ec.generate_private_key(ec.SECP256R1())
    kc = ec.generate_private_key(ec.SECP256R1())
    agora = datetime.datetime.now(datetime.timezone.utc)
    falso = (x509.CertificateBuilder().subject_name(c.subject).issuer_name(inter.subject)
             .public_key(kc.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(agora - datetime.timedelta(minutes=5)).not_valid_after(agora + datetime.timedelta(days=1))
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
             .sign(ac, hashes.SHA256()))
    fc, fk = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    with open(fc, "wb") as f:
        f.write(falso.public_bytes(serialization.Encoding.PEM))
    with open(fk, "wb") as f:
        f.write(kc.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    negado, st = status_sem_sucesso("/restrito", fc, fk)
    shutil.rmtree(tmp, ignore_errors=True)
    exigir(negado, "um certificado de cliente emitido por AC desconhecida foi aceito")
    return "cliente aceito; sem certificado e com AC desconhecida, negado"


def t8(mat):
    inter = cert("pki", "inter", "inter.crt")
    rev = cert("clientes", "revogado.crt")
    exigir(rev.issuer == inter.subject and assinado_por(rev, inter.public_key()), "revogado.crt deve ser emitido pela intermediária")
    exigir(cn(rev.subject) == f"{mat}-revogado", f"o CN do certificado revogado deve ser '{mat}-revogado'")

    with open(caminho("web", "crl.pem"), "rb") as f:
        texto = f.read()
    blocos = [b"-----BEGIN X509 CRL-----" + p for p in texto.split(b"-----BEGIN X509 CRL-----")[1:]]
    exigir(len(blocos) == 2, "crl.pem deve conter duas LCRs (raiz e intermediária)")
    lcrs = [x509.load_pem_x509_crl(b) for b in blocos]
    raiz = cert("pki", "raiz", "raiz.crt")
    lcr_inter = next((l for l in lcrs if l.issuer == inter.subject), None)
    lcr_raiz = next((l for l in lcrs if l.issuer == raiz.subject), None)
    exigir(lcr_inter is not None and lcr_raiz is not None, "crl.pem deve conter a LCR da raiz e a LCR da intermediária")
    exigir(lcr_inter.is_signature_valid(inter.public_key()), "a LCR da intermediária não foi assinada pela intermediária")
    exigir(lcr_raiz.is_signature_valid(raiz.public_key()), "a LCR da raiz não foi assinada pela raiz")
    exigir(lcr_inter.get_revoked_certificate_by_serial_number(rev.serial_number) is not None,
           "o número de série de revogado.crt não está na LCR da intermediária")
    aluno = cert("clientes", "aluno.crt")
    exigir(lcr_inter.get_revoked_certificate_by_serial_number(aluno.serial_number) is None, "aluno.crt não deveria estar revogado")

    negado, st = status_sem_sucesso("/restrito", caminho("clientes", "revogado.crt"), caminho("clientes", "revogado.key"))
    exigir(negado, "o nginx aceitou o certificado revogado (falta ssl_crl ou o serviço não foi reiniciado)")
    status, _, _ = requisicao_segura("/restrito", caminho("clientes", "aluno.crt"), caminho("clientes", "aluno.key"))
    exigir(status == 200, f"após a revogação, o certificado válido do aluno deveria continuar aceito (status {status})")
    return f"revogado negado ({st}); aluno aceito"


def t9(mat):
    p7s = caminho("t9", "termo.p7s")
    termo = os.path.join(MAT, "t9", "termo.txt")
    raiz = caminho("pki", "raiz", "raiz.crt")
    tmp = tempfile.mkdtemp()
    signer = os.path.join(tmp, "signer.pem")
    ok, msg = openssl("cms", "-verify", "-binary", "-inform", "DER", "-in", p7s, "-content", termo,
                      "-CAfile", raiz, "-signer", signer, "-out", os.devnull)
    exigir(ok, f"a assinatura CMS não foi validada a partir da raiz (a intermediária foi incluída?): {msg.splitlines()[-1] if msg else ''}")
    with open(signer, "rb") as f:
        assinante = x509.load_pem_x509_certificate(f.read())
    exigir(assinante == cert("clientes", "aluno.crt"), "o assinante do .p7s deve ser aluno.crt")

    alterado = os.path.join(tmp, "alterado.txt")
    with open(termo, "rb") as f, open(alterado, "wb") as g:
        g.write(f.read().replace(b"exclusiva", b"compartilhada"))
    ok, _ = openssl("cms", "-verify", "-binary", "-inform", "DER", "-in", p7s, "-content", alterado,
                    "-CAfile", raiz, "-out", os.devnull)
    shutil.rmtree(tmp, ignore_errors=True)
    exigir(not ok, "a assinatura deveria falhar para um termo alterado (usar assinatura destacada, sem -nodetach)")
    return "CMS destacado, assinante aluno.crt, cadeia até a raiz"


# ------------------------------------------------------------------------- execução
def main():
    env = ler_env()
    mat = env.get("MATRICULA", "")
    linhas = []

    def saida(t=""):
        print(t)
        linhas.append(t)

    saida("=" * 78)
    saida("CORREÇÃO AUTOMÁTICA — Assinaturas Digitais e Certificados (Docker)")
    saida(f"Matrícula: {mat or '(não preenchida)'}   Nome: {env.get('NOME', '')}")
    saida(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")
    saida("=" * 78)
    if not mat:
        saida("Preencher MATRICULA em trabalho/aluno.env antes da correção.")
        sys.exit(1)

    total = 0
    for tarefa, func in (("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5),
                         ("T6", t6), ("T7", t7), ("T8", t8), ("T9", t9)):
        try:
            detalhe = func(mat)
            total += PESOS[tarefa]
            saida(f"[OK]       {tarefa} ({PESOS[tarefa]:>2}%) {TITULOS[tarefa]}")
            saida(f"           {detalhe}")
        except Falha as e:
            saida(f"[PENDENTE] {tarefa} ({PESOS[tarefa]:>2}%) {TITULOS[tarefa]}")
            saida(f"           {e}")
        except Exception as e:  # erro inesperado: mostra o tipo para facilitar a depuração
            saida(f"[PENDENTE] {tarefa} ({PESOS[tarefa]:>2}%) {TITULOS[tarefa]}")
            saida(f"           erro ao corrigir: {type(e).__name__}: {e}")
    saida("-" * 78)
    saida(f"Percentual concluído: {total}%  (conferência automática; a avaliação final é do professor)")

    if os.path.isdir(SAIDA):
        with open(os.path.join(SAIDA, "resultado_correcao.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(linhas) + "\n")


if __name__ == "__main__":
    main()
