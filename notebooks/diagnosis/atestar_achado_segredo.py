# Databricks notebook source
# MAGIC %md
# MAGIC **Notebook name:** atestar_achado_segredo.
# MAGIC **Functionality:** recupera a string exata que gerou um achado do secret scanner e
# MAGIC mostra o contexto em que ela aparece, para atestar falso positivo com evidencia.
# MAGIC
# MAGIC O scanner grava apenas o SHA-256 do campo `Raw` do TruffleHog. Este notebook roda
# MAGIC o mesmo binario sobre um unico arquivo, le o `Raw` diretamente e confere o hash
# MAGIC contra o que esta na tabela. Se o hash bater, a string na tela e a mesma que gerou
# MAGIC a linha do achado — sem inferencia.
# MAGIC
# MAGIC Nao grava nada. Nao copia o arquivo para volume. O conteudo fica no driver e some.

# COMMAND ----------

dbutils.widgets.text("caminho", "/Repos/.../arquivo.json", "Caminho do objeto no workspace")
dbutils.widgets.text("hash_esperado", "", "secret_sha256 da tabela (opcional)")

CAMINHO = dbutils.widgets.get("caminho").strip()
HASH_ESPERADO = dbutils.widgets.get("hash_esperado").strip().lower()

# COMMAND ----------

# MAGIC %run ../Includes/install_sat_sdk

# COMMAND ----------

# MAGIC %run ../Utils/initialize

# COMMAND ----------

# MAGIC %run ../Utils/common

# COMMAND ----------

import base64, hashlib, json, os, subprocess, requests
from urllib.parse import quote

LOCAL = "/tmp/atestar_alvo"
os.makedirs(LOCAL, exist_ok=True)
destino = os.path.join(LOCAL, os.path.basename(CAMINHO) or "alvo")

ctx = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
base_url = ctx.apiUrl().get()
token = ctx.apiToken().get()

r = requests.get(
    f"{base_url}/api/2.0/workspace/export?path={quote(CAMINHO)}&direct_download=false&format=SOURCE",
    headers={"Authorization": f"Bearer {token}"}, timeout=60)
if r.status_code != 200:
    raise SystemExit(f"Falha ao exportar ({r.status_code}): {r.text[:300]}")

conteudo = base64.b64decode(r.json()["content"])
with open(destino, "wb") as f:
    f.write(conteudo)
print(f"Arquivo em {destino} — {len(conteudo)} bytes")

# COMMAND ----------

# Roda o TruffleHog do mesmo jeito que o scanner: detectores nativos e depois os
# customizados. A diferenca e que aqui lemos o `Raw` em vez de hashear.
def rodar(args, rotulo):
    p = subprocess.run(args, capture_output=True, text=True, timeout=300)
    achados = []
    for linha in (p.stdout or "").splitlines():
        try:
            d = json.loads(linha)
        except Exception:
            continue
        raw = d.get("Raw", "")
        if not raw:
            continue
        achados.append({
            "origem": rotulo,
            "detector": (d.get("ExtraData") or {}).get("name") or d.get("DetectorName", "?"),
            "verified": d.get("Verified", False),
            "raw": raw,
            "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        })
    return achados

resultados  = rodar([Config.TRUFFLEHOG_BINARY, "filesystem", destino, "--no-update", "-j"], "nativo")
resultados += rodar([Config.TRUFFLEHOG_BINARY, "filesystem", destino, "--no-update",
                     "--config", Config.TRUFFLEHOG_CONFIG, "-j"], "customizado")

print(f"{len(resultados)} achado(s) neste arquivo\n")

# COMMAND ----------

texto = conteudo.decode("utf-8", errors="replace")

vistos = set()
for a in resultados:
    chave = (a["detector"], a["sha256"])
    if chave in vistos:
        continue
    vistos.add(chave)

    bate = " <<< BATE COM A TABELA" if HASH_ESPERADO and a["sha256"] == HASH_ESPERADO else ""
    print("=" * 78)
    print(f"detector : {a['detector']}   ({a['origem']})")
    print(f"verified : {a['verified']}")
    print(f"sha256   : {a['sha256']}{bate}")
    print(f"tamanho  : {len(a['raw'])} caracteres")
    print(f"string   : {a['raw']}")

    # Onde a string aparece e o que esta em volta. O contexto e o que decide:
    # valor de campo de dado ou credencial atribuida a uma chave de configuracao.
    ocorrencias = []
    inicio = 0
    while True:
        i = texto.find(a["raw"], inicio)
        if i < 0:
            break
        ocorrencias.append(i)
        inicio = i + 1
        if len(ocorrencias) >= 3:
            break

    print(f"ocorrencias no arquivo: {len(ocorrencias)}{'+' if len(ocorrencias)>=3 else ''}")
    for i in ocorrencias:
        ini, fim = max(0, i - 160), min(len(texto), i + len(a["raw"]) + 160)
        print("-" * 78)
        print(texto[ini:fim].replace("\n", " "))
    print()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Como atestar
# MAGIC
# MAGIC Olhe o **contexto** impresso acima, nao a string isolada.
# MAGIC
# MAGIC **E falso positivo quando** a string aparece como *valor de dado*: dentro de um
# MAGIC array de registros, num campo de identificador, hash, assinatura ou blob base64,
# MAGIC sem nenhuma chave que a nomeie como credencial. Alta entropia sozinha nao e segredo.
# MAGIC
# MAGIC **Nao e falso positivo quando** a string esta atribuida a uma chave que a declara:
# MAGIC `token`, `password`, `secret`, `apiKey`, `connectionString`, `sas`, `client_secret` —
# MAGIC ou quando `verified = true` num detector nativo.
# MAGIC
# MAGIC **Cuidado com `verified = true` em detector customizado.** Ali a verificacao usa o
# MAGIC `endpoint` e o `successRanges` definidos em `configs/custom_trufflehog_detectors.yaml`.
# MAGIC Se o endpoint devolver 200 para qualquer entrada, `verified` nao prova nada. Antes de
# MAGIC tratar como incidente, leia o bloco `verify` daquele detector.
# MAGIC
# MAGIC ## Registrar a decisao
# MAGIC
# MAGIC ```sql
# MAGIC UPDATE <schema>.scan_exception_dispositions
# MAGIC SET decisao = 'falso_positivo',
# MAGIC     responsavel = 'nome',
# MAGIC     observacao  = 'string aparece como valor de dado em campo X, sem chave de credencial'
# MAGIC WHERE disposition_id = '<id>';
# MAGIC ```

# COMMAND ----------

# Limpeza: o arquivo nao fica no driver depois da analise.
import shutil
shutil.rmtree(LOCAL, ignore_errors=True)
print("Copia local removida.")
