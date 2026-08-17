# Databricks notebook source
# MAGIC %md
# MAGIC **Functionality:** Initializes the setup and configuration of the **Security Analysis Tool (SAT)**.
# MAGIC

# COMMAND ----------

# MAGIC %run ./diagnosis/pre_run_config_check

# COMMAND ----------

# MAGIC %run ./Includes/install_sat_sdk

# COMMAND ----------

# MAGIC %run ./Utils/initialize

# COMMAND ----------

# MAGIC %run ./Utils/common

# COMMAND ----------

hostname = (
    dbutils.notebook.entry_point.getDbutils()
    .notebook()
    .getContext()
    .apiUrl()
    .getOrElse(None)
)
cloud_type = getCloudType(hostname)

# COMMAND ----------

# Parametros do bundle repassados aos notebooks filhos. Widgets do job NAO sao
# herdados por dbutils.notebook.run: sem isso, os filhos caem no valor do secret
# scope e podem escrever no schema errado (ex.: schema de producao em vez do canary).
_child_args = {
    k: str(json_[k])
    for k in ("analysis_schema_name", "maxpages", "timebetweencalls", "use_parallel_runs")
    if k in json_
}

def run_notebook(notebook_path, timeout):
    status = dbutils.notebook.run(notebook_path, timeout, _child_args)
    if status != "OK":
        loggr.exception(f"Error Encountered in {notebook_path}", status)
        dbutils.notebook.exit()

# COMMAND ----------

notebooks = [
    ("1. list_account_workspaces_to_conf_file", 3000),
    ("3. test_connections", 12000),
    ("4. enable_workspaces_for_sat", 3000),
    ("5. import_dashboard_template_lakeview", 3000),
]

for notebook, timeout in notebooks:
    status=run_notebook(f"{basePath()}/notebooks/Setup/{notebook}", timeout)

# COMMAND ----------

spark.sql(f"DROP DATABASE IF EXISTS {json_['intermediate_schema']} CASCADE")