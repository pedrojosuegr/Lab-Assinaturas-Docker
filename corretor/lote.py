# -*- coding: utf-8 -*-
"""Geração de lotes de pacotes assinados (ECDSA P-256 / SHA-256) para a tarefa T2.

Usado para gerar o lote fixo de materiais/t2 e, na correção, um lote novo e aleatório."""
import os
import random

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

DEFEITOS = ["outra_chave", "conteudo_alterado", "sem_assinatura", "assinatura_corrompida", "assinatura_trocada"]


def _assinar(priv, dados):
    return priv.sign(dados, ec.ECDSA(hashes.SHA256()))


def gerar_lote(pasta, quantidade=12, semente=None):
    """Grava o lote em `pasta` e devolve a lista ordenada dos nomes dos pacotes autênticos."""
    rnd = random.Random(semente)
    os.makedirs(os.path.join(pasta, "pacotes"), exist_ok=True)
    fabricante = ec.generate_private_key(ec.SECP256R1())
    impostor = ec.generate_private_key(ec.SECP256R1())
    with open(os.path.join(pasta, "fabricante.pub"), "wb") as f:
        f.write(fabricante.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    tipos = DEFEITOS + ["ok"] * (quantidade - len(DEFEITOS))
    rnd.shuffle(tipos)
    autenticos = []
    for i, tipo in enumerate(tipos, start=1):
        nome = f"atualizacao-{i:02d}.bin"
        dados = (f"Pacote {i:02d} - firmware do controlador, versao 3.{i}\n".encode()
                 + bytes(rnd.getrandbits(8) for _ in range(256)))
        assinatura = _assinar(fabricante, dados)
        if tipo == "outra_chave":
            assinatura = _assinar(impostor, dados)
        elif tipo == "conteudo_alterado":
            dados = dados[:-1] + bytes([dados[-1] ^ 0x5A])
        elif tipo == "assinatura_corrompida":
            assinatura = bytearray(assinatura)
            assinatura[-3] ^= 0x01
            assinatura = bytes(assinatura)
        elif tipo == "assinatura_trocada":
            assinatura = _assinar(fabricante, dados + b"versao anterior")
        elif tipo == "ok":
            autenticos.append(nome)

        caminho = os.path.join(pasta, "pacotes", nome)
        with open(caminho, "wb") as f:
            f.write(dados)
        if tipo != "sem_assinatura":
            with open(caminho + ".sig", "wb") as f:
                f.write(assinatura)
    return sorted(autenticos)


if __name__ == "__main__":
    import sys
    print(gerar_lote(sys.argv[1], semente=int(sys.argv[2]) if len(sys.argv) > 2 else None))
