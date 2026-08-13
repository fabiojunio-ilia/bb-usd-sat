# Bundle SAT (BB) — dev/prd por Databricks Asset Bundle

Bundle concreto e versionado (opção B2). A configuracao **nao secreta** vive no
`databricks.yml` (fonte de verdade, revisavel em PR); os **segredos** continuam
no secret scope, gerados pelo instalador em `dabs/`.

## Deploy

    databricks bundle validate -t dev
    databricks bundle deploy -t dev
    databricks bundle deploy -t prd

## Como a config chega aos notebooks

O `databricks.yml` declara variaveis por ambiente (catalogo, schema, flags de
execucao). Os jobs em `resources/*.yml` passam essas variaveis como
`base_parameters`. O `notebooks/Utils/initialize.py` tem um gancho que le esses
parametros e sobrescreve o `json_`, mantendo o segredo vindo do scope. Se rodar
interativo, sem parametros, mantem o default.

Variaveis parametrizadas: `analysis_schema_name` (catalogo.schema), `maxpages`,
`timebetweencalls`, `use_parallel_runs`, `secrets_max_parallel_workspaces`.

## Preencher antes do primeiro deploy (TODO no databricks.yml)

- `host` do workspace DEV.
- `warehouse_id` de dev e prd.
- `run_as_sp` (Application ID do service principal) de prd.
- `spark_version` (LTS vigente) e confirmar `node_type_id`.
- Confirmar o catalogo de prd: o `sat.log` mostra `usd_prd`, o scaffold usava `usd_dsv`.
- Cluster policy do BB: se obrigatoria, adicionar `policy_id` no `new_cluster`.

## Verificar no primeiro deploy

- Resolucao do `notebook_path` via `${workspace.file_path}`: confirmar que os
  notebooks e o diretorio `configs/` ficam irmaos sob `files/`, pois o
  `basePath()` do SAT deriva o caminho de `configs` a partir do path do notebook.
- Secret scope: gerar com o instalador em `dabs/` antes do primeiro run.

## Fora do escopo desta etapa

- Jobs do BrickHound (Permissions Analysis): experimentais e hoje parados no BB.
  Portar depois, se ativados.
- Esteira CI/CD: esta etapa deixa o codigo pronto para deploy manual dev->prd.
