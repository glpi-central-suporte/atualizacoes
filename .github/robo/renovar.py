#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════
#  renovar.py — robô do "estou vivo" (renovacao.json) — D-041, D-042
#  Central de Suporte · repositório público de versões · v0.8.6 · 29/10/2026
# ═══════════════════════════════════════════════════════════════════════════
#  RESPONSABILIDADE
#    Assinar o renovacao.json que dá VALIDADE ao manifesto.json atual.
#    Roda no GitHub Actions: todo mês e logo depois de cada publicação.
#  O QUE ELE CONFERE ANTES DE ASSINAR
#    1. manifesto.json com assinatura válida de uma chave de VERSÕES
#       (chaves públicas em CHAVES_VERSOES, no workflow). Manifesto adulterado
#       → NÃO renova (e o job falha, para aparecer o alerta).
#    2. formato 1 e produto "central-suporte".
#  O QUE ELE NÃO PODE
#    A chave de RENOVAÇÃO (segredo RENOVACAO_CHAVE) só assina a validade.
#    Não autoriza instalador, não retira versão, não encerra servidor.
#  QUANDO RENOVA
#    - renovacao.json ausente, de outro manifesto, ou com menos de 75 dias de
#      validade (com o mês de intervalo, a validade nunca cai abaixo de ~60).
#  FORMATOS (iguais ao app: Core/Atualizacao/Renovacao.cs e AssinaturaEcdsa.cs)
#    Assinatura: ECDSA P-256 + SHA-256, r||s (64 bytes), base64 numa linha.
#    Chave privada: PKCS#8 DER em base64. Chave pública: SPKI DER em base64.
#  DEPENDÊNCIA
#    Só python3-cryptography do próprio Ubuntu (apt, assinado pelo Ubuntu).
#  SAÍDA
#    0 = renovou, não precisava, ou ainda não há manifesto · 1 = recusou
#  MUDANÇAS
#    0.8.6 · 29/10/2026 — criação.
#    0.8.7 · 29/10/2026 — sem manifesto.json ainda → sai em paz (sem erro).
# ═══════════════════════════════════════════════════════════════════════════
import base64, datetime, hashlib, json, os, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

VALIDADE_DIAS = 90
RENOVAR_ABAIXO_DE_DIAS = 75
FMT = "%Y-%m-%dT%H:%M:%SZ"


def parar(msg):
    print("RECUSADO: " + msg)
    sys.exit(1)


def le(nome):
    with open(nome, "rb") as f:
        return f.read()


def confere(dados, sig_texto, chaves_b64):
    try:
        bruto = base64.b64decode(sig_texto.strip(), validate=True)
    except Exception:
        return False
    if len(bruto) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(bruto[:32], "big"), int.from_bytes(bruto[32:], "big"))
    for k in chaves_b64:
        try:
            pub = serialization.load_der_public_key(base64.b64decode(k))
            if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
                continue
            pub.verify(der, dados, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def assina(dados, chave_privada_b64):
    priv = serialization.load_der_private_key(base64.b64decode(chave_privada_b64), password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey) or priv.curve.name != "secp256r1":
        parar("a chave de renovação não é ECDSA P-256")
    r, s = decode_dss_signature(priv.sign(dados, ec.ECDSA(hashes.SHA256())))
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode() + "\n"


def main():
    chaves_versoes = [c.strip() for c in os.environ.get("CHAVES_VERSOES", "").split(",") if c.strip()]
    chave_renovacao = os.environ.get("RENOVACAO_CHAVE", "").strip()
    forcar = os.environ.get("FORCAR", "") == "sim"
    if not chaves_versoes:
        parar("CHAVES_VERSOES vazio no workflow")
    if not chave_renovacao:
        parar("segredo RENOVACAO_CHAVE não configurado")

    if not os.path.exists("manifesto.json"):
        print("Ainda não há manifesto.json: nada para renovar.")
        return
    manifesto = le("manifesto.json")
    if not confere(manifesto, le("manifesto.sig").decode("ascii", "replace"), chaves_versoes):
        parar("assinatura do manifesto.json NÃO confere com as chaves de VERSÕES")
    m = json.loads(manifesto)
    if m.get("formato") != 1 or m.get("produto") != "central-suporte" or not isinstance(m.get("sequencia"), int):
        parar("manifesto fora do formato 1 / produto errado")
    sha = hashlib.sha256(manifesto).hexdigest()
    agora = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    if not forcar and os.path.exists("renovacao.json"):
        try:
            r = json.loads(le("renovacao.json"))
            ate = datetime.datetime.strptime(r["validoAte"], FMT).replace(tzinfo=datetime.timezone.utc)
            if r.get("sha256Manifesto") == sha and r.get("sequenciaManifesto") == m["sequencia"] \
                    and ate - agora > datetime.timedelta(days=RENOVAR_ABAIXO_DE_DIAS):
                print(f"Não precisa: renovação atual vale até {r['validoAte']} para a sequência {m['sequencia']}.")
                return
        except Exception:
            pass  # renovação ilegível → renova

    ren = {
        "formato": 1,
        "produto": "central-suporte",
        "sequenciaManifesto": m["sequencia"],
        "sha256Manifesto": sha,
        "emitidoEm": agora.strftime(FMT),
        "validoAte": (agora + datetime.timedelta(days=VALIDADE_DIAS)).strftime(FMT),
    }
    dados = (json.dumps(ren, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    sig = assina(dados, chave_renovacao)
    with open("renovacao.json", "wb") as f:
        f.write(dados)
    with open("renovacao.sig", "w", encoding="ascii", newline="\n") as f:
        f.write(sig)
    print(f"Renovado: sequência {m['sequencia']}, válido até {ren['validoAte']}.")


if __name__ == "__main__":
    main()
