# Databricks notebook source
# DBTITLE 1,Introdução
# MAGIC %md
# MAGIC # Playbook: Detecção de Movimentação de Dados via Downloads no Workspace
# MAGIC
# MAGIC ## Contexto
# MAGIC
# MAGIC Este playbook investiga a regra de detecção do **SAT (Security Analysis Tool)** chamada **"Potential Data Movement via Workspace Downloads"**.
# MAGIC
# MAGIC ### O Problema
# MAGIC
# MAGIC A regra original do SAT tipicamente monitora apenas dois tipos de eventos:
# MAGIC - `workspace.workspaceExport` — exportação de notebooks (código-fonte)
# MAGIC - `filesystem.filesGet` — download de arquivos via Files API ou Volumes
# MAGIC
# MAGIC Porém, o **vetor mais crítico de exfiltração de dados** — o download de resultados de queries — é capturado por eventos **frequentemente AUSENTES** da regra:
# MAGIC - `notebook.downloadPreviewResults` — download de resultados de uma célula/query
# MAGIC - `notebook.downloadLargeResults` — download de resultados grandes demais para exibir no notebook
# MAGIC
# MAGIC ### O que este Playbook cobre
# MAGIC
# MAGIC | Evento | Serviço | O que detecta | Risco |
# MAGIC |--------|---------|---------------|-------|
# MAGIC | `workspaceExport` | `workspace` | Exportação de código de notebooks | Vazamento de lógica, credenciais hardcoded |
# MAGIC | `filesGet` | `filesystem` | Download de arquivos (Volumes, workspace files) | Exfiltração de dados em arquivo |
# MAGIC | `downloadPreviewResults` | `notebook` | Download de resultados de queries | **Exfiltração direta de dados** |
# MAGIC | `downloadLargeResults` | `notebook` | Download de resultados grandes | **Exfiltração em massa de dados** |
# MAGIC
# MAGIC ### Pré-requisitos
# MAGIC - Acesso à tabela `system.access.audit` (system tables habilitadas)
# MAGIC - Acesso à tabela `system.access.workspaces_latest` (para nomes dos workspaces)
# MAGIC - As queries cobrem **todos os workspaces** da conta, pois `system.access.audit` agrega logs de todos os workspaces
# MAGIC
# MAGIC ### Como usar
# MAGIC Execute cada passo sequencialmente. Os resultados de cada célula SQL ajudarão a entender o panorama de downloads no seu ambiente e identificar atividades suspeitas.

# COMMAND ----------

# DBTITLE 1,Passo 1 — Discovery
# MAGIC %md
# MAGIC ## Passo 1: Discovery — Quais eventos de download existem no seu ambiente?
# MAGIC
# MAGIC A primeira etapa é entender **quais tipos de download estão ocorrendo** em cada workspace. Esta query agrupa os eventos por workspace, serviço e ação para dar uma visão geral.
# MAGIC
# MAGIC > **Nota:** Eventos `filesGet` que acessam caminhos internos do Delta Lake (`_delta_log/`), Change Data Feed (`_change_data/`) e artefatos internos (`WorkspaceInternal/`) são **excluídos** por serem operações internas da plataforma, não downloads de usuários.

# COMMAND ----------

# DBTITLE 1,Discovery — Eventos de download por workspace
# MAGIC %sql
# MAGIC -- Passo 1: Discovery — Eventos de download agrupados por workspace, serviço e ação
# MAGIC -- Período: últimos 30 dias | Cobre todos os workspaces da conta
# MAGIC
# MAGIC SELECT
# MAGIC   a.workspace_id,
# MAGIC   COALESCE(w.workspace_name, CONCAT('workspace_', a.workspace_id)) AS workspace_name,
# MAGIC   a.service_name,
# MAGIC   a.action_name,
# MAGIC   COUNT(*) AS total_events,
# MAGIC   COUNT(DISTINCT a.user_identity.email) AS unique_users,
# MAGIC   MIN(a.event_time) AS first_event,
# MAGIC   MAX(a.event_time) AS last_event
# MAGIC FROM system.access.audit a
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON a.workspace_id = w.workspace_id
# MAGIC WHERE
# MAGIC   a.event_date >= CURRENT_DATE() - INTERVAL 30 DAYS
# MAGIC   AND (
# MAGIC     -- Exportação de notebooks (código-fonte)
# MAGIC     (a.service_name = 'workspace' AND a.action_name = 'workspaceExport')
# MAGIC     -- Download de arquivos (excluindo operações internas)
# MAGIC     OR (a.service_name = 'filesystem' AND a.action_name = 'filesGet'
# MAGIC         AND a.request_params.path NOT LIKE '%/_delta_log/%'
# MAGIC         AND a.request_params.path NOT LIKE '%/_change_data/%'
# MAGIC         AND a.request_params.path NOT LIKE '%/WorkspaceInternal/%')
# MAGIC     -- Download de resultados de queries (VETOR CRÍTICO)
# MAGIC     OR (a.service_name = 'notebook' AND a.action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
# MAGIC   )
# MAGIC GROUP BY a.workspace_id, w.workspace_name, a.service_name, a.action_name
# MAGIC ORDER BY total_events DESC

# COMMAND ----------

# DBTITLE 1,Passo 2 — Quem está fazendo downloads
# MAGIC %md
# MAGIC ## Passo 2: Quem está fazendo downloads e de onde?
# MAGIC
# MAGIC Agora identificamos **quais usuários** estão realizando downloads e de quais locais.
# MAGIC
# MAGIC ### Como interpretar o campo `user_agent`
# MAGIC
# MAGIC O campo `user_agent` é essencial para distinguir o **método** utilizado:
# MAGIC
# MAGIC | Padrão no `user_agent` | Significado | Risco |
# MAGIC |------------------------|-------------|-------|
# MAGIC | `Mozilla/...` ou `Chrome/...` | Download manual via **interface web (UI)** | Médio — ação deliberada do usuário |
# MAGIC | `databricks-cli/...` | Acesso via **Databricks CLI** | Alto — pode ser script automatizado |
# MAGIC | `python-requests/...` | Acesso via **API programática (Python)** | Alto — extração automatizada |
# MAGIC | `databricks-sdk-java/...` | Acesso via **SDK Java** | Alto — integração externa |
# MAGIC | `curl/...` | Acesso via **cURL** | Alto — script ou ferramenta externa |
# MAGIC
# MAGIC ### Campo `source_ip_address`
# MAGIC
# MAGIC Mostra o IP de origem da requisição. IPs fora da rede corporativa podem indicar acesso não autorizado ou uso de VPN pessoal.

# COMMAND ----------

# DBTITLE 1,Atividade de download por usuário e workspace
# MAGIC %sql
# MAGIC -- Passo 2: Atividade de download por usuário e workspace
# MAGIC -- Período: últimos 30 dias | Cobre todos os workspaces da conta
# MAGIC
# MAGIC SELECT
# MAGIC   a.user_identity.email AS user_email,
# MAGIC   a.workspace_id,
# MAGIC   COALESCE(w.workspace_name, CONCAT('workspace_', a.workspace_id)) AS workspace_name,
# MAGIC   
# MAGIC   -- Contagem por tipo de evento
# MAGIC   COUNT(CASE WHEN a.service_name = 'workspace' AND a.action_name = 'workspaceExport' THEN 1 END) AS notebook_exports,
# MAGIC   COUNT(CASE WHEN a.service_name = 'filesystem' AND a.action_name = 'filesGet' THEN 1 END) AS file_downloads,
# MAGIC   COUNT(CASE WHEN a.service_name = 'notebook' AND a.action_name = 'downloadPreviewResults' THEN 1 END) AS result_downloads,
# MAGIC   COUNT(CASE WHEN a.service_name = 'notebook' AND a.action_name = 'downloadLargeResults' THEN 1 END) AS large_result_downloads,
# MAGIC   COUNT(*) AS total_events,
# MAGIC   
# MAGIC   -- Contexto adicional
# MAGIC   COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
# MAGIC   COUNT(DISTINCT a.user_agent) AS distinct_user_agents,
# MAGIC   MIN(a.event_time) AS first_event,
# MAGIC   MAX(a.event_time) AS last_event
# MAGIC
# MAGIC FROM system.access.audit a
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON a.workspace_id = w.workspace_id
# MAGIC WHERE
# MAGIC   a.event_date >= CURRENT_DATE() - INTERVAL 30 DAYS
# MAGIC   AND (
# MAGIC     (a.service_name = 'workspace' AND a.action_name = 'workspaceExport')
# MAGIC     OR (a.service_name = 'filesystem' AND a.action_name = 'filesGet'
# MAGIC         AND a.request_params.path NOT LIKE '%/_delta_log/%'
# MAGIC         AND a.request_params.path NOT LIKE '%/_change_data/%'
# MAGIC         AND a.request_params.path NOT LIKE '%/WorkspaceInternal/%')
# MAGIC     OR (a.service_name = 'notebook' AND a.action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
# MAGIC   )
# MAGIC GROUP BY a.user_identity.email, a.workspace_id, w.workspace_name
# MAGIC ORDER BY total_events DESC

# COMMAND ----------

# DBTITLE 1,Passo 3 — Downloads de Resultados de Queries
# MAGIC %md
# MAGIC ## Passo 3: Detalhes dos Downloads de Resultados de Queries (Vetor Crítico)
# MAGIC
# MAGIC Esta é a categoria **mais perigosa** de exfiltração — usuários fazendo download de **dados reais** resultantes de queries.
# MAGIC
# MAGIC ### Campos-chave para investigação
# MAGIC
# MAGIC | Campo | Descrição |
# MAGIC |-------|----------|
# MAGIC | `notebookId` | ID do notebook onde o resultado foi gerado |
# MAGIC | `notebookFullPath` | Caminho completo do notebook |
# MAGIC | `commandId` | Identifica **qual célula específica** gerou os dados baixados |
# MAGIC | `source_ip_address` | IP de origem do download |
# MAGIC | `user_agent` | Método utilizado (browser, API, CLI) |
# MAGIC
# MAGIC ### Diferença entre os dois eventos
# MAGIC - **`downloadPreviewResults`**: Usuário clicou no botão de download dos resultados visíveis na célula
# MAGIC - **`downloadLargeResults`**: Usuário baixou resultados que eram **grandes demais** para exibir inline — indica volumes maiores de dados

# COMMAND ----------

# DBTITLE 1,Detalhes dos downloads de resultados de queries
# MAGIC %sql
# MAGIC -- Passo 3: Detalhes dos downloads de resultados de queries
# MAGIC -- Período: últimos 30 dias | Eventos mais críticos para exfiltração de dados
# MAGIC
# MAGIC SELECT
# MAGIC   a.event_time,
# MAGIC   a.event_date,
# MAGIC   a.workspace_id,
# MAGIC   COALESCE(w.workspace_name, CONCAT('workspace_', a.workspace_id)) AS workspace_name,
# MAGIC   a.user_identity.email AS user_email,
# MAGIC   a.action_name,
# MAGIC   a.request_params.notebookId AS notebook_id,
# MAGIC   a.request_params.notebookFullPath AS notebook_path,
# MAGIC   a.request_params.commandId AS command_id,
# MAGIC   a.source_ip_address,
# MAGIC   a.user_agent,
# MAGIC   
# MAGIC   -- Classificação do método de acesso
# MAGIC   CASE
# MAGIC     WHEN a.user_agent LIKE '%Mozilla%' OR a.user_agent LIKE '%Chrome%' THEN 'Browser (UI)'
# MAGIC     WHEN a.user_agent LIKE '%databricks-cli%' THEN 'Databricks CLI'
# MAGIC     WHEN a.user_agent LIKE '%python-requests%' OR a.user_agent LIKE '%databricks-sdk-python%' THEN 'Python SDK/API'
# MAGIC     WHEN a.user_agent LIKE '%databricks-sdk-java%' THEN 'Java SDK'
# MAGIC     WHEN a.user_agent LIKE '%curl%' THEN 'cURL'
# MAGIC     ELSE 'Outro'
# MAGIC   END AS access_method
# MAGIC
# MAGIC FROM system.access.audit a
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON a.workspace_id = w.workspace_id
# MAGIC WHERE
# MAGIC   a.event_date >= CURRENT_DATE() - INTERVAL 30 DAYS
# MAGIC   AND a.service_name = 'notebook'
# MAGIC   AND a.action_name IN ('downloadPreviewResults', 'downloadLargeResults')
# MAGIC ORDER BY a.event_time DESC
# MAGIC LIMIT 500

# COMMAND ----------

# DBTITLE 1,Passo 4 — Exports de Notebooks
# MAGIC %md
# MAGIC ## Passo 4: Detalhes dos Exports de Notebooks (Código-Fonte)
# MAGIC
# MAGIC O evento `workspaceExport` captura quando usuários exportam o **código-fonte** de notebooks. Isso pode representar risco de vazamento de propriedade intelectual, lógica de negócio ou até credenciais hardcoded.
# MAGIC
# MAGIC ### Campos-chave
# MAGIC
# MAGIC | Campo | Descrição |
# MAGIC |-------|----------|
# MAGIC | `notebookFullPath` | Caminho do notebook exportado |
# MAGIC | `workspaceExportFormat` | Formato da exportação |
# MAGIC | `workspaceExportDirectDownload` | Se foi download direto (true/false) |
# MAGIC
# MAGIC ### Formatos de exportação e risco
# MAGIC
# MAGIC | Formato | Descrição | Risco |
# MAGIC |---------|-----------|-------|
# MAGIC | `DBC` | Databricks archive (pode conter múltiplos notebooks) | **Alto** — exportação em massa |
# MAGIC | `SOURCE` | Código-fonte bruto (.py, .sql, .r, .scala) | Médio — código legível |
# MAGIC | `HTML` | Notebook renderizado com resultados | Médio — pode conter dados |
# MAGIC | `JUPYTER` | Formato .ipynb (Jupyter) | Médio — código + resultados |
# MAGIC | `R_MARKDOWN` | Formato R Markdown | Baixo — apenas código R |

# COMMAND ----------

# DBTITLE 1,Detalhes dos exports de notebooks
# MAGIC %sql
# MAGIC -- Passo 4: Detalhes dos exports de notebooks (código-fonte)
# MAGIC -- Período: últimos 30 dias | Identifica exportações de notebooks
# MAGIC
# MAGIC SELECT
# MAGIC   a.event_time,
# MAGIC   a.event_date,
# MAGIC   a.workspace_id,
# MAGIC   COALESCE(w.workspace_name, CONCAT('workspace_', a.workspace_id)) AS workspace_name,
# MAGIC   a.user_identity.email AS user_email,
# MAGIC   a.request_params.notebookFullPath AS notebook_path,
# MAGIC   a.request_params.workspaceExportFormat AS export_format,
# MAGIC   a.request_params.workspaceExportDirectDownload AS direct_download,
# MAGIC   a.source_ip_address,
# MAGIC   a.user_agent,
# MAGIC   
# MAGIC   -- Classificação de risco pelo formato
# MAGIC   CASE
# MAGIC     WHEN a.request_params.workspaceExportFormat = 'DBC' THEN 'ALTO - Archive (múltiplos notebooks)'
# MAGIC     WHEN a.request_params.workspaceExportFormat = 'HTML' THEN 'MÉDIO - Pode conter resultados'
# MAGIC     WHEN a.request_params.workspaceExportFormat = 'JUPYTER' THEN 'MÉDIO - Código + resultados'
# MAGIC     WHEN a.request_params.workspaceExportFormat = 'SOURCE' THEN 'MÉDIO - Código-fonte bruto'
# MAGIC     ELSE 'BAIXO'
# MAGIC   END AS format_risk,
# MAGIC   
# MAGIC   -- Método de acesso
# MAGIC   CASE
# MAGIC     WHEN a.user_agent LIKE '%Mozilla%' OR a.user_agent LIKE '%Chrome%' THEN 'Browser (UI)'
# MAGIC     WHEN a.user_agent LIKE '%databricks-cli%' THEN 'Databricks CLI'
# MAGIC     WHEN a.user_agent LIKE '%python-requests%' OR a.user_agent LIKE '%databricks-sdk-python%' THEN 'Python SDK/API'
# MAGIC     WHEN a.user_agent LIKE '%curl%' THEN 'cURL'
# MAGIC     ELSE 'Outro'
# MAGIC   END AS access_method
# MAGIC
# MAGIC FROM system.access.audit a
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON a.workspace_id = w.workspace_id
# MAGIC WHERE
# MAGIC   a.event_date >= CURRENT_DATE() - INTERVAL 30 DAYS
# MAGIC   AND a.service_name = 'workspace'
# MAGIC   AND a.action_name = 'workspaceExport'
# MAGIC ORDER BY a.event_time DESC
# MAGIC LIMIT 500

# COMMAND ----------

# DBTITLE 1,Passo 5 — Downloads de Arquivos
# MAGIC %md
# MAGIC ## Passo 5: Downloads de Arquivos (Files API / Volumes)
# MAGIC
# MAGIC O evento `filesystem.filesGet` captura downloads de arquivos via **Files API** ou **UI de Volumes**.
# MAGIC
# MAGIC ### Filtragem de ruído
# MAGIC
# MAGIC É fundamental filtrar operações internas que geram `filesGet` mas **não representam downloads de usuários**:
# MAGIC
# MAGIC | Caminho excluído | Motivo |
# MAGIC |------------------|--------|
# MAGIC | `/_delta_log/` | Metadados internos do Delta Lake |
# MAGIC | `/_change_data/` | Change Data Feed (CDF) interno |
# MAGIC | `/WorkspaceInternal/` | Artefatos internos (MLflow, etc.) |
# MAGIC
# MAGIC ### Classificação por tipo de arquivo
# MAGIC
# MAGIC A query abaixo classifica os arquivos baixados pela extensão, facilitando a identificação de downloads de **dados** (CSV, Parquet, JSON) versus **código** ou **configuração**.

# COMMAND ----------

# DBTITLE 1,Detalhes dos downloads de arquivos
# MAGIC %sql
# MAGIC -- Passo 5: Downloads de arquivos via Files API / Volumes
# MAGIC -- Período: últimos 30 dias | Exclui operações internas do Delta Lake e sistema
# MAGIC
# MAGIC SELECT
# MAGIC   a.event_time,
# MAGIC   a.event_date,
# MAGIC   a.workspace_id,
# MAGIC   COALESCE(w.workspace_name, CONCAT('workspace_', a.workspace_id)) AS workspace_name,
# MAGIC   a.user_identity.email AS user_email,
# MAGIC   a.request_params.path AS file_path,
# MAGIC   a.source_ip_address,
# MAGIC   a.user_agent,
# MAGIC   
# MAGIC   -- Classificação do tipo de arquivo pela extensão
# MAGIC   CASE
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.csv' THEN 'CSV (dados tabulares)'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.parquet' THEN 'Parquet (dados colunares)'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.json' THEN 'JSON'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.xlsx' OR LOWER(a.request_params.path) LIKE '%.xls' THEN 'Excel'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.txt' THEN 'Texto'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.pdf' THEN 'PDF'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.py' THEN 'Python (código)'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.sql' THEN 'SQL (código)'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.yaml' OR LOWER(a.request_params.path) LIKE '%.yml' THEN 'YAML (configuração)'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%/MLmodel' OR LOWER(a.request_params.path) LIKE '%.pkl' THEN 'Modelo ML'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%.tar.gz' OR LOWER(a.request_params.path) LIKE '%.zip' THEN 'Arquivo compactado'
# MAGIC     ELSE 'Outro'
# MAGIC   END AS file_type,
# MAGIC   
# MAGIC   -- Classificação de risco pelo tipo
# MAGIC   CASE
# MAGIC     WHEN LOWER(a.request_params.path) RLIKE '\.(csv|parquet|xlsx|xls|json|tar\.gz|zip)$' THEN 'ALTO - Dados'
# MAGIC     WHEN LOWER(a.request_params.path) RLIKE '\.(py|sql|r|scala)$' THEN 'MÉDIO - Código'
# MAGIC     WHEN LOWER(a.request_params.path) LIKE '%/MLmodel' OR LOWER(a.request_params.path) LIKE '%.pkl' THEN 'MÉDIO - Modelo ML'
# MAGIC     ELSE 'BAIXO'
# MAGIC   END AS file_risk,
# MAGIC   
# MAGIC   -- Método de acesso
# MAGIC   CASE
# MAGIC     WHEN a.user_agent LIKE '%Mozilla%' OR a.user_agent LIKE '%Chrome%' THEN 'Browser (UI)'
# MAGIC     WHEN a.user_agent LIKE '%databricks-cli%' THEN 'Databricks CLI'
# MAGIC     WHEN a.user_agent LIKE '%python-requests%' OR a.user_agent LIKE '%databricks-sdk-python%' THEN 'Python SDK/API'
# MAGIC     WHEN a.user_agent LIKE '%curl%' THEN 'cURL'
# MAGIC     ELSE 'Outro'
# MAGIC   END AS access_method
# MAGIC
# MAGIC FROM system.access.audit a
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON a.workspace_id = w.workspace_id
# MAGIC WHERE
# MAGIC   a.event_date >= CURRENT_DATE() - INTERVAL 30 DAYS
# MAGIC   AND a.service_name = 'filesystem'
# MAGIC   AND a.action_name = 'filesGet'
# MAGIC     -- Excluir operações internas
# MAGIC   AND a.request_params.path NOT LIKE '%/_delta_log/%'
# MAGIC   AND a.request_params.path NOT LIKE '%/_change_data/%'
# MAGIC   AND a.request_params.path NOT LIKE '%/WorkspaceInternal/%'
# MAGIC ORDER BY a.event_time DESC
# MAGIC LIMIT 500

# COMMAND ----------

# DBTITLE 1,Passo 6 — Análise Cross-Workspace
# MAGIC %md
# MAGIC ## Passo 6: Análise Cross-Workspace — Usuários com Atividade Suspeita
# MAGIC
# MAGIC Esta análise identifica padrões que podem indicar **exfiltração sistemática** de dados:
# MAGIC
# MAGIC ### Indicadores de comportamento suspeito
# MAGIC
# MAGIC | Indicador | Por que é suspeito |
# MAGIC |-----------|-------------------|
# MAGIC | Downloads em **múltiplos workspaces** | Usuário coletando dados de vários ambientes |
# MAGIC | **Volume alto** de downloads | Possível data hoarding ou extração automatizada |
# MAGIC | Downloads de **resultados grandes** (`downloadLargeResults`) | Extração de volumes significativos de dados |
# MAGIC | **Múltiplos IPs** de origem | Acesso de locais diferentes ou uso de proxies |
# MAGIC | Atividade em **muitos dias** consecutivos | Padrão persistente de extração |
# MAGIC
# MAGIC > **Importante:** A query abaixo filtra usuários com mais de 5 eventos no período. Ajuste esse threshold conforme o padrão normal do seu ambiente.

# COMMAND ----------

# DBTITLE 1,Usuários com padrões suspeitos de download
# MAGIC %sql
# MAGIC -- Passo 6: Usuários com padrões suspeitos de download (cross-workspace)
# MAGIC -- Período: últimos 30 dias | Filtra usuários com > 5 eventos
# MAGIC
# MAGIC SELECT
# MAGIC   a.user_identity.email AS user_email,
# MAGIC   
# MAGIC   -- Amplitude cross-workspace
# MAGIC   COUNT(DISTINCT a.workspace_id) AS workspaces_count,
# MAGIC   CONCAT_WS(', ', COLLECT_SET(COALESCE(w.workspace_name, CONCAT('ws_', a.workspace_id)))) AS workspaces_list,
# MAGIC   
# MAGIC   -- Volume por tipo de evento
# MAGIC   COUNT(*) AS total_events,
# MAGIC   COUNT(CASE WHEN a.service_name = 'workspace' AND a.action_name = 'workspaceExport' THEN 1 END) AS notebook_exports,
# MAGIC   COUNT(CASE WHEN a.service_name = 'filesystem' AND a.action_name = 'filesGet' THEN 1 END) AS file_downloads,
# MAGIC   COUNT(CASE WHEN a.service_name = 'notebook' AND a.action_name = 'downloadPreviewResults' THEN 1 END) AS result_downloads,
# MAGIC   COUNT(CASE WHEN a.service_name = 'notebook' AND a.action_name = 'downloadLargeResults' THEN 1 END) AS large_result_downloads,
# MAGIC   
# MAGIC   -- Indicadores de risco
# MAGIC   COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
# MAGIC   COUNT(DISTINCT CASE WHEN a.service_name = 'workspace' THEN a.request_params.notebookFullPath END) AS distinct_notebooks_exported,
# MAGIC   COUNT(DISTINCT CASE WHEN a.service_name = 'filesystem' THEN a.request_params.path END) AS distinct_files_downloaded,
# MAGIC   COUNT(DISTINCT a.event_date) AS days_active,
# MAGIC   
# MAGIC   -- Período de atividade
# MAGIC   MIN(a.event_time) AS first_event,
# MAGIC   MAX(a.event_time) AS last_event
# MAGIC
# MAGIC FROM system.access.audit a
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON a.workspace_id = w.workspace_id
# MAGIC WHERE
# MAGIC   a.event_date >= CURRENT_DATE() - INTERVAL 30 DAYS
# MAGIC   AND (
# MAGIC     (a.service_name = 'workspace' AND a.action_name = 'workspaceExport')
# MAGIC     OR (a.service_name = 'filesystem' AND a.action_name = 'filesGet'
# MAGIC         AND a.request_params.path NOT LIKE '%/_delta_log/%'
# MAGIC         AND a.request_params.path NOT LIKE '%/_change_data/%'
# MAGIC         AND a.request_params.path NOT LIKE '%/WorkspaceInternal/%')
# MAGIC     OR (a.service_name = 'notebook' AND a.action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
# MAGIC   )
# MAGIC GROUP BY a.user_identity.email
# MAGIC HAVING COUNT(*) > 5
# MAGIC ORDER BY total_events DESC

# COMMAND ----------

# DBTITLE 1,Passo 7 — Regra de Detecção Recomendada
# MAGIC %md
# MAGIC ## Passo 7: Regra de Detecção Recomendada para o SAT/SIEM
# MAGIC
# MAGIC Esta é a **query de detecção consolidada** que cobre **todos os 4 vetores** de exfiltração. Pode ser adaptada para:
# MAGIC
# MAGIC | Destino | Como usar |
# MAGIC |---------|-----------|
# MAGIC | **Databricks SQL Alert** | Agende esta query e configure um alerta quando retornar resultados |
# MAGIC | **Splunk** | Converta os filtros para SPL usando os mesmos `service_name` e `action_name` |
# MAGIC | **Microsoft Sentinel** | Use os mesmos campos no KQL sobre os diagnostic logs do Databricks |
# MAGIC | **SAT personalizado** | Adicione esta query como check adicional no Security Analysis Tool |
# MAGIC
# MAGIC ### Classificação de risco
# MAGIC
# MAGIC | Nível | Critério |
# MAGIC |-------|----------|
# MAGIC | **CRITICAL** | `downloadLargeResults` — volume grande de dados extraídos |
# MAGIC | **HIGH** | `workspaceExport` com formato `DBC` ou `HTML` — export em massa ou com dados |
# MAGIC | **MEDIUM** | `downloadPreviewResults` ou `workspaceExport` com formato `SOURCE`/`JUPYTER` |
# MAGIC | **LOW** | `filesGet` de arquivos individuais |
# MAGIC
# MAGIC > **Período:** A query abaixo cobre os **últimos 7 dias** para uso como regra de detecção recorrente. Ajuste conforme a frequência de execução do alerta.

# COMMAND ----------

# DBTITLE 1,Regra de detecção consolidada — Todos os vetores
# MAGIC %sql
# MAGIC -- Passo 7: Regra de detecção consolidada — Todos os vetores de exfiltração
# MAGIC -- Período: últimos 7 dias (para uso como alerta recorrente)
# MAGIC -- Adapte para Splunk, Sentinel ou SQL Alert conforme necessário
# MAGIC
# MAGIC WITH all_download_events AS (
# MAGIC   -- Vetor 1: Exportação de notebooks
# MAGIC   SELECT
# MAGIC     a.event_time,
# MAGIC     a.workspace_id,
# MAGIC     a.user_identity.email AS user_email,
# MAGIC     'Notebook Code Export' AS threat_category,
# MAGIC     a.request_params.notebookFullPath AS resource_path,
# MAGIC     CONCAT('Formato: ', COALESCE(a.request_params.workspaceExportFormat, 'N/A'),
# MAGIC            ' | Direct Download: ', COALESCE(a.request_params.workspaceExportDirectDownload, 'N/A')) AS detail,
# MAGIC     a.source_ip_address,
# MAGIC     a.user_agent,
# MAGIC     CASE
# MAGIC       WHEN a.request_params.workspaceExportFormat IN ('DBC', 'HTML') THEN 'HIGH'
# MAGIC       ELSE 'MEDIUM'
# MAGIC     END AS risk_level
# MAGIC   FROM system.access.audit a
# MAGIC   WHERE a.event_date >= CURRENT_DATE() - INTERVAL 7 DAYS
# MAGIC     AND a.service_name = 'workspace'
# MAGIC     AND a.action_name = 'workspaceExport'
# MAGIC
# MAGIC   UNION ALL
# MAGIC
# MAGIC   -- Vetor 2: Download de arquivos
# MAGIC   SELECT
# MAGIC     a.event_time,
# MAGIC     a.workspace_id,
# MAGIC     a.user_identity.email AS user_email,
# MAGIC     'File Download' AS threat_category,
# MAGIC     a.request_params.path AS resource_path,
# MAGIC     CONCAT('Tipo: ',
# MAGIC       CASE
# MAGIC         WHEN LOWER(a.request_params.path) RLIKE '\.(csv|parquet|xlsx|xls|json)$' THEN 'Dados'
# MAGIC         WHEN LOWER(a.request_params.path) RLIKE '\.(py|sql|r|scala)$' THEN 'Código'
# MAGIC         WHEN LOWER(a.request_params.path) LIKE '%/MLmodel' OR LOWER(a.request_params.path) LIKE '%.pkl' THEN 'Modelo ML'
# MAGIC         ELSE 'Outro'
# MAGIC       END
# MAGIC     ) AS detail,
# MAGIC     a.source_ip_address,
# MAGIC     a.user_agent,
# MAGIC     CASE
# MAGIC       WHEN LOWER(a.request_params.path) RLIKE '\.(csv|parquet|xlsx|xls|json|tar\.gz|zip)$' THEN 'MEDIUM'
# MAGIC       ELSE 'LOW'
# MAGIC     END AS risk_level
# MAGIC   FROM system.access.audit a
# MAGIC   WHERE a.event_date >= CURRENT_DATE() - INTERVAL 7 DAYS
# MAGIC     AND a.service_name = 'filesystem'
# MAGIC     AND a.action_name = 'filesGet'
# MAGIC     AND a.request_params.path NOT LIKE '%/_delta_log/%'
# MAGIC     AND a.request_params.path NOT LIKE '%/_change_data/%'
# MAGIC     AND a.request_params.path NOT LIKE '%/WorkspaceInternal/%'
# MAGIC
# MAGIC   UNION ALL
# MAGIC
# MAGIC   -- Vetor 3: Download de resultados de queries (VETOR CRÍTICO)
# MAGIC   SELECT
# MAGIC     a.event_time,
# MAGIC     a.workspace_id,
# MAGIC     a.user_identity.email AS user_email,
# MAGIC     CASE
# MAGIC       WHEN a.action_name = 'downloadLargeResults' THEN 'Large Results Download'
# MAGIC       ELSE 'Query Results Download'
# MAGIC     END AS threat_category,
# MAGIC     COALESCE(a.request_params.notebookFullPath, CONCAT('notebookId: ', a.request_params.notebookId)) AS resource_path,
# MAGIC     CONCAT('CommandId: ', COALESCE(a.request_params.commandId, 'N/A')) AS detail,
# MAGIC     a.source_ip_address,
# MAGIC     a.user_agent,
# MAGIC     CASE
# MAGIC       WHEN a.action_name = 'downloadLargeResults' THEN 'CRITICAL'
# MAGIC       ELSE 'MEDIUM'
# MAGIC     END AS risk_level
# MAGIC   FROM system.access.audit a
# MAGIC   WHERE a.event_date >= CURRENT_DATE() - INTERVAL 7 DAYS
# MAGIC     AND a.service_name = 'notebook'
# MAGIC     AND a.action_name IN ('downloadPreviewResults', 'downloadLargeResults')
# MAGIC )
# MAGIC
# MAGIC SELECT
# MAGIC   e.event_time,
# MAGIC   e.workspace_id,
# MAGIC   COALESCE(w.workspace_name, CONCAT('workspace_', e.workspace_id)) AS workspace_name,
# MAGIC   e.user_email,
# MAGIC   e.threat_category,
# MAGIC   e.resource_path,
# MAGIC   e.detail,
# MAGIC   e.source_ip_address,
# MAGIC   e.user_agent,
# MAGIC   e.risk_level
# MAGIC FROM all_download_events e
# MAGIC LEFT JOIN system.access.workspaces_latest w
# MAGIC   ON e.workspace_id = w.workspace_id
# MAGIC ORDER BY
# MAGIC   CASE e.risk_level
# MAGIC     WHEN 'CRITICAL' THEN 1
# MAGIC     WHEN 'HIGH' THEN 2
# MAGIC     WHEN 'MEDIUM' THEN 3
# MAGIC     WHEN 'LOW' THEN 4
# MAGIC   END,
# MAGIC   e.event_time DESC

# COMMAND ----------

# DBTITLE 1,Próximos Passos
# MAGIC %md
# MAGIC ## Próximos Passos
# MAGIC
# MAGIC ### 1. Desabilitar downloads desnecessários
# MAGIC No **Admin Console > Settings > Security**, desabilite os toggles que não são necessários para o seu ambiente:
# MAGIC - **Notebook results download** — impede download de resultados de células
# MAGIC - **Notebook exporting** — impede exportação de notebooks
# MAGIC - **SQL results download** — impede download de resultados de queries SQL
# MAGIC - **Results table clipboard features** — impede cópia de dados para clipboard
# MAGIC
# MAGIC > ⚠️ Essas configurações são **por workspace**. Aplique em cada workspace da conta.
# MAGIC
# MAGIC ### 2. Agendar alerta automático
# MAGIC Use a query do **Passo 7** como base para um **Databricks SQL Alert**:
# MAGIC - Agende execução a cada 1 hora (ou conforme sua política)
# MAGIC - Configure notificação por email ou Slack quando a query retornar eventos de risco `CRITICAL` ou `HIGH`
# MAGIC - Ajuste o período da query para corresponder à frequência de execução
# MAGIC
# MAGIC ### 3. Integrar com SIEM
# MAGIC Exporte os eventos para seu SIEM via:
# MAGIC - **Diagnostic logs** (CloudWatch, Azure Monitor, ou Cloud Logging conforme seu cloud provider) — tempo real
# MAGIC - **System tables** (`system.access.audit`) — para consultas históricas
# MAGIC - Adapte os filtros `service_name` / `action_name` para o formato do seu SIEM (SPL, KQL, etc.)
# MAGIC
# MAGIC ### 4. Revisar padrões regularmente
# MAGIC Execute o **Passo 6** (Análise Cross-Workspace) periodicamente para identificar:
# MAGIC - Usuários com volume anormal de downloads
# MAGIC - Novos padrões de acesso programático (API/CLI)
# MAGIC - Atividade de usuários que saíram da organização
# MAGIC
# MAGIC ### 5. Considerar isolação de rede
# MAGIC Para ambientes altamente sensíveis:
# MAGIC - **Private Link** — limita acesso ao workspace apenas via rede privada
# MAGIC - **IP Access Lists** — restringe IPs permitidos para acessar o workspace
# MAGIC - **Egress firewall rules** — controla tráfego de saída dos clusters
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ### Referências
# MAGIC - [Databricks Security Best Practices (PDF)](https://www.databricks.com/trust/security-features/best-practices)
# MAGIC - [Audit Log Reference](https://docs.databricks.com/en/admin/account-settings/audit-logs.html)
# MAGIC - [Manage Notebook Features](https://docs.databricks.com/en/admin/workspace-settings/notebooks.html)
# MAGIC - [Security Analysis Tool (SAT) — GitHub](https://github.com/databricks-labs/security-analysis-tool)