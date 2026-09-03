# Databricks notebook source
# MAGIC %md
# MAGIC **Notebook name:** common.
# MAGIC **Functionality:** routines used across the project

# COMMAND ----------

# Schemas minimos para colecoes que legitimamente podem vir vazias (workspace
# sem PATs, sem IP access list, sem mounts etc.). Sem isso a tabela nao e criada
# e o check correspondente falha com "view not found" em vez de avaliar como
# conforme com zero achados. "Nao avaliado" e "sem risco" sao coisas diferentes
# num relatorio de seguranca. Colunas = as referenciadas pelos checks.
EMPTY_COLLECTION_SCHEMAS = {
    'tokens': 'comment string, created_by_username string, token_id string, expiry_time bigint',
    'ipaccesslist': 'label string, list_type string, enabled boolean',
    'dbfssettingsdirs': 'path string',
    'dbfssettingsmounts': 'path string',
    'globalscripts': 'name string, created_by string, enabled boolean',
    'legacyinitscripts': 'path string, is_dir boolean',
    'vector_search_endpoint_list': 'name string, endpoint_type string',
    'account_ipaccess_list': 'label string, list_type string, address_count int, enabled boolean',
}


def bootstrap(viewname, func, **kwargs):
    """bootstrap with function and store resulting dataframe as a global temp view
    if the function doesn't return a value, creates an empty dataframe and corresponding view
    :param str viewname - name of the view
    :param func - Name of the function to call
    :**kwargs - named args to pass to the function

    """
    import json
    import pandas as pd

    from pyspark.sql.types import StructType
    from pyspark.sql.functions import col, schema_of_json, from_json, concat_ws, collect_list

    apiDF = None
    try:
        lst = func(**kwargs)
        if lst:
            lstjson = [json.dumps(ifld) for ifld in lst]
            apiDF = spark.createDataFrame([(x,) for x in lstjson], ["json_string"])
            # Parse the JSON strings using the schema string
            apiDF = apiDF.select(from_json(col("json_string"), process_json_schema(apiDF)).alias("data")).select("data.*")
            #display(apiDF)
        else:
            _base = viewname.rsplit('_', 1)[0] if viewname.rsplit('_', 1)[-1].isdigit() else viewname
            _ddl = EMPTY_COLLECTION_SCHEMAS.get(_base)
            if _ddl:
                apiDF = spark.createDataFrame([], _ddl)
                loggr.info(f"No results; creating empty `{viewname}` with schema so checks evaluate on zero rows")
            else:
                apiDF = spark.createDataFrame([], StructType([]))
                loggr.info("No Results!")
        if len(apiDF.take(1)) > 0 or len(apiDF.schema) > 0:
            apiDF.write.option("delta.columnMapping.mode", "name").mode("overwrite").saveAsTable(viewname)
            loggr.info(f"Table created: `{viewname}`")
    except Exception:
        loggr.exception("Exception encountered")

# COMMAND ----------


def handleAnalysisErrors(e):
    """
    Handle AnalysisException when sql is run. This is raised when fields in sql are not found.
    """
    v = e.getMessage()
    vlst = v.lower().split(" ")
    strField = ""
    if len(vlst) > 2 and vlst[0] == "cannot" and vlst[1] == "resolve":
        strField = "cannot find field " + vlst[2] + " in SQL"
    elif (
        len(vlst) > 8
        and vlst[0] == "[unresolved_column.with_suggestion]"
        and vlst[5] == "function"
        and vlst[6] == "parameter"
    ):
        strField = "cannot find field " + vlst[9] + " in SQL"
    elif (
        len(vlst) > 8
        and vlst[0] == "[unresolved_column.without_suggestion]"
        and vlst[5] == "function"
        and vlst[6] == "parameter"
    ):
        strField = "cannot find field " + vlst[9] + " in SQL"
    elif len(vlst) > 3 and vlst[1] == "such" and vlst[2] == "struct":
        strField = "cannot find struct field `" + vlst[4] + "` in SQL"
    elif len(vlst) > 2 and "Did you mean" in v:
        strField = "field " + vlst[1] + " not found"
    else:
        strField = v
    return strField


# COMMAND ----------


def sqlctrl(workspace_id, sqlstr, funcrule, info=False):  # lambda
    """Executes sql, tests the result with the function and write results to control table
    :param sqlstr sql to execute
    :param funcrule rule to execute to check if violation passed or failed
    :param infoStats boolean to insert into stats as opposed to control table
    """
    import pyspark.sql.utils
    from pyspark.sql.types import StructType

    try:
        df = spark.sql(sqlstr)
    except pyspark.sql.utils.AnalysisException as e:
        s = handleAnalysisErrors(e)
        df = spark.createDataFrame([], StructType([]))
        loggr.info(s)
    try:
        if funcrule:
            display(df)
            if info:
                name, value, category = funcrule(df)
                insertIntoInfoTable(workspace_id, name, value, category)
            else:
                ctrlname, ctrlscore, additional_details = funcrule(df)
                if len(additional_details) == 0 and ctrlscore == 0:
                    additional_details = {
                        "message": "No deviations from the security best practices found for this check"
                    }

                insertIntoControlTable(
                    workspace_id, ctrlname, ctrlscore, additional_details
                )
    except Exception as e:
        loggr.exception(e)


# COMMAND ----------


def sqldisplay(sqlstr):
    """
    execute a sql and display the dataframe.
    :param str sqlstr SQL to execute
    """
    import pyspark.sql.utils

    try:
        df = spark.sql(sqlstr)
        display(df)
    except pyspark.sql.utils.AnalysisException as e:
        s = handleAnalysisErrors(e)
        loggr.info(s)
    except Exception as e:
        loggr.exception(e)


# COMMAND ----------


# --- Gravacao em lote (v1) -------------------------------------------------
# Antes: cada check fazia 1 SELECT max(runID) + 1 INSERT de 1 linha (~200
# micro-transacoes Delta por workspace). Agora: run_id e lido uma vez e os
# resultados acumulam em memoria; flushControlTables() grava 1 lote por tabela.
# Chamado no fim de cada notebook de analise; como rede de protecao, o buffer
# tambem descarrega sozinho a cada _FLUSH_THRESHOLD linhas.
_pending_checks = []
_pending_info = []
_cached_run_id = None
_FLUSH_THRESHOLD = 200


def _get_run_id():
    global _cached_run_id
    if _cached_run_id is None:
        _cached_run_id = spark.sql(
            f'select max(runID) from {json_["analysis_schema_name"]}.run_number_table'
        ).collect()[0][0]
    return _cached_run_id


def flushControlTables():
    """Grava em lote os resultados acumulados de checks e infos."""
    global _pending_checks, _pending_info
    if _pending_checks:
        values = ",\n".join(
            "('{}', '{}', cast({} as int), from_json('{}', 'MAP<STRING,STRING>'), {}, cast({} as timestamp))".format(*row)
            for row in _pending_checks
        )
        spark.sql(
            "INSERT INTO {}.`security_checks` (`workspaceid`, `id`, `score`, `additional_details`, `run_id`, `check_time`) VALUES {}".format(
                json_["analysis_schema_name"], values))
        loggr.info(f"flushControlTables: {len(_pending_checks)} check(s) gravados em lote")
        _pending_checks = []
    if _pending_info:
        values = ",\n".join(
            "('{}','{}', from_json('{}', 'MAP<STRING,STRING>'), '{}', '{}', cast({} as timestamp))".format(*row)
            for row in _pending_info
        )
        spark.sql(
            "INSERT INTO {}.`account_info` (`workspaceid`,`name`, `value`, `category`, `run_id`, `check_time`) VALUES {}".format(
                json_["analysis_schema_name"], values))
        loggr.info(f"flushControlTables: {len(_pending_info)} info(s) gravadas em lote")
        _pending_info = []


def insertIntoControlTable(workspace_id, id, score, additional_details):
    """
    Acumula resultado de check para gravacao em lote (ver flushControlTables).
    """
    import json
    import time

    ts = time.time()
    run_id = _get_run_id()
    jsonstr = json.dumps(additional_details).replace("'", "''")
    _pending_checks.append((workspace_id, id, score, jsonstr, run_id, ts))
    if len(_pending_checks) >= _FLUSH_THRESHOLD:
        flushControlTables()


# COMMAND ----------


def insertIntoInfoTable(workspace_id, name, value, category):
    """
    Insert values into an information table
    :param str name name of the information
    :param value additional_details additional details of the value
    :param str category of info for filtering
    """
    import json
    import time

    ts = time.time()
    run_id = _get_run_id()
    jsonstr = json.dumps(value).replace("'", "''")
    safe_name = name.replace("'", "''")
    safe_category = category.replace("'", "''")
    _pending_info.append((workspace_id, safe_name, jsonstr, safe_category, run_id, ts))
    if len(_pending_info) >= _FLUSH_THRESHOLD:
        flushControlTables()


# COMMAND ----------


def getCloudType(url):
    if ".cloud." in url:
        return "aws"
    elif ".azuredatabricks." in url:
        return "azure"
    elif ".gcp." in url:
        return "gcp"
    return ""


# COMMAND ----------


def readWorkspaceConfigFile():
    import pandas as pd

    prefix = getConfigPath()

    dfa = pd.DataFrame()
    schema = "workspace_id string, deployment_url string, workspace_name string,workspace_status string, connection_test boolean, analysis_enabled boolean"
    dfexist = spark.createDataFrame([], schema)
    try:
        dict = {
            "workspace_id": "str",
            "connection_test": "bool",
            "analysis_enabled": "bool",
        }
        dfa = pd.read_csv(f"{prefix}/workspace_configs.csv", header=0, dtype=dict)
        if len(dfa) > 0:
            dfa = dfa.where(dfa.notna(), None)
            dfexist = spark.createDataFrame(dfa.values.tolist(), schema)
    except FileNotFoundError:
        print("Missing workspace Config file")
        return
    except pd.errors.EmptyDataError as e:
        pass
    return dfexist


# COMMAND ----------


def getWorkspaceConfig():
    df = spark.sql(
        f"""select * from {json_["analysis_schema_name"]}.account_workspaces"""
    )
    return df


# COMMAND ----------


# Read the best practices file. (security_best_practices.csv)
# Sice User configs are present in this file, the file is renamed (to security_best_practices_user)
# This is needed only on bootstrap, subsequetly the database is the master copy of the user configuration
# Every time the values are altered, the _user file can be regenerated - but it is more as FYI
def readBestPracticesConfigsFile():
    security_best_practices_exists = spark.catalog.tableExists( f'{json_["analysis_schema_name"]}.security_best_practices')
    if not security_best_practices_exists:
        import shutil
        from os.path import exists

        import pandas as pd

        hostname = (
            dbutils.notebook.entry_point.getDbutils()
            .notebook()
            .getContext()
            .apiUrl()
            .getOrElse(None)
        )
        cloud_type = getCloudType(hostname)
        doc_url = cloud_type + "_doc_url"

        prefix = getConfigPath()
        origfile = f"{prefix}/security_best_practices.csv"
        
        schema_list = [
            "id",
            "check_id",
            "category",
            "check",
            "evaluation_value",
            "severity",
            "recommendation",
            "aws",
            "azure",
            "gcp",
            "enable",
            "logic",
            "api",
            doc_url,
        ]

        schema = """id int, check_id string,category string,check string, evaluation_value int,severity string,
                recommendation string,aws int,azure int,gcp int,enable int, logic string, api string,  doc_url string"""

        security_best_practices_pd = pd.read_csv(
            origfile, header=0, usecols=schema_list
        ).rename(columns={doc_url: "doc_url"})
        
        security_best_practices_pd = security_best_practices_pd.where(security_best_practices_pd.notna(), None)
        security_best_practices = spark.createDataFrame(
            security_best_practices_pd.values.tolist(), schema
        ).select(
            "id",
            "check_id",
            "category",
            "check",
            "evaluation_value",
            "severity",
            "recommendation",
            "doc_url",
            "aws",
            "azure",
            "gcp",
            "enable",
            "logic",
            "api",
        )
        security_best_practices.write.format("delta").mode("overwrite").saveAsTable(
            json_["analysis_schema_name"] + ".security_best_practices"
        )
        _set_table_comment(
            json_["analysis_schema_name"], "security_best_practices",
            "Reference catalog of all SAT security checks. Each row defines one check: its category, severity, "
            "actionable recommendation, and which clouds it applies to. Both id and check_id are unique per row. "
            "Join to security_checks on id to interpret results."
        )
        _set_column_comments(json_["analysis_schema_name"], "security_best_practices", {
            "id":               "Unique integer identifier for this security check — no two rows may share the same value",
            "check_id":         "Unique human-readable check code (e.g. DP-1, GOV-5, NS-3, IA-2, INFO-4) — no two rows may share the same value",
            "category":         "Security category: Data Protection, Governance, Identity & Access, Network Security, or Informational",
            "check":            "Short descriptive name of the security check",
            "evaluation_value": "Threshold used during evaluation. -1 means a presence/absence check (any violation = fail); positive integer means the acceptable limit",
            "severity":         "Risk level if this check fails: Critical, High, Medium, or Low",
            "recommendation":   "Actionable guidance for remediating a failed check",
            "doc_url":          "Databricks documentation URL for this security topic",
            "aws":              "1 if this check applies to AWS-hosted workspaces, 0 otherwise",
            "azure":            "1 if this check applies to Azure-hosted workspaces, 0 otherwise",
            "gcp":              "1 if this check applies to GCP-hosted workspaces, 0 otherwise",
            "enable":           "1 if this check is currently enabled for evaluation, 0 if disabled",
            "logic":            "Human-readable description of the check evaluation logic",
            "api":              "Databricks API endpoint or command used to collect data for this check",
        })
        display(security_best_practices)


# COMMAND ----------

# Read and load the SAT and DASF mapping file. (SAT_DASF_mapping.csv)
def load_sat_dasf_mapping():
  import pandas as pd
  from os.path import exists
  import shutil

  
  prefix = getConfigPath()
  origfile = f'{prefix}/sat_dasf_mapping.csv'
    
  schema_list = ['sat_id', 'dasf_control_id','dasf_control_name']

  schema = '''sat_id int, dasf_control_id string,dasf_control_name string'''

  sat_dasf_mapping_pd = pd.read_csv(origfile, header=0, usecols=schema_list)

  sat_dasf_mapping_pd = sat_dasf_mapping_pd.where(sat_dasf_mapping_pd.notna(), None)
  sat_dasf_mapping = (spark.createDataFrame(sat_dasf_mapping_pd.values.tolist(), schema)
                            .select('sat_id', 'dasf_control_id','dasf_control_name'))
    
  sat_dasf_mapping.write.format('delta').mode('overwrite').saveAsTable(json_["analysis_schema_name"]+'.sat_dasf_mapping')
  _set_table_comment(
      json_["analysis_schema_name"], "sat_dasf_mapping",
      "Maps SAT security checks to Databricks AI Security Framework (DASF) controls for validating each workspace against data and AI security best practices. "
      "The dasf_control_id field encodes both the control ID and name (e.g. DASF-33:Manage credentials securely) "
      "and may be comma-separated when one SAT check maps to multiple DASF controls."
  )
  _set_column_comments(json_["analysis_schema_name"], "sat_dasf_mapping", {
      "sat_id":            "SAT check ID — corresponds to the id column in security_best_practices",
      "dasf_control_id":   "Databricks AI Security Framework (DASF) control identifier including the control name "
                           "(format: DASF-N:Control Name). Comma-separated when mapping to multiple controls.",
      "dasf_control_name": "DASF control name — currently NULL; the name is encoded in dasf_control_id",
  })
  display(sat_dasf_mapping)


# COMMAND ----------


def getSecurityBestPracticeRecord(id, cloud_type):
    df = spark.sql(
        f"""select * from {json_["analysis_schema_name"]}.security_best_practices where id = '{id}' """
    )
    dict_elems = {}
    enable = 0
    if "none" not in cloud_type and df is not None and df.count() > 0:
        dict_elems = df.collect()[0]
        if dict_elems[cloud_type] == 1 and dict_elems["enable"] == 1:
            enable = 1

    return (enable, dict_elems)


# COMMAND ----------


def getConfigPath():
    return f"{basePath()}/configs"


# COMMAND ----------

def basePath():
    path = (
        dbutils.notebook.entry_point.getDbutils()
        .notebook()
        .getContext()
        .notebookPath()
        .get()
    )
    path = path[: path.find("/notebooks")]
    return f"/Workspace{path}"


# COMMAND ----------


def create_schema():
    schema = json_["analysis_schema_name"]
    run_table_existed = spark.catalog.tableExists(f"{schema}.run_number_table")
    df = spark.sql(f'CREATE DATABASE IF NOT EXISTS {schema}')
    df = spark.sql(f'CREATE DATABASE IF NOT EXISTS {json_["intermediate_schema"]}')
    spark.sql(
        f"COMMENT ON SCHEMA {schema} IS "
        f"'Databricks Security Analysis Tool (SAT) results. Contains security check findings, "
        f"workspace configurations, secret scan results, and Permission Analysis graph data (BrickHound), "
        f"all evaluated against Databricks best practices.'"
    )
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.run_number_table (
                        runID BIGINT GENERATED ALWAYS AS IDENTITY,
                        check_time TIMESTAMP
                        )
                        USING DELTA"""
    )
    # A run_number_table recebe um INSERT por workspace, em paralelo. Reaplicar
    # COMMENT/ALTER a cada execucao colide com esses INSERTs e derruba a alocacao
    # do run_id com MetadataChangedException.
    if not run_table_existed:
        try:
            _set_table_comment(
                schema, "run_number_table",
                "Sequence table that issues a unique run_id for each SAT analysis execution. "
                "Join all other tables to this on run_id to correlate findings from the same run. "
                "Typically has one row per SAT job execution."
            )
            _set_column_comments(schema, "run_number_table", {
                "runID":      "Auto-incrementing unique identifier for each SAT analysis run",
                "check_time": "Timestamp when this SAT run was initiated",
            })
        except Exception as exc:
            print(f"run_number_table comments skipped: {exc}")


# COMMAND ----------


def insertNewBatchRun():
    import time

    ts = time.time()
    df = spark.sql(
        f'insert into {json_["analysis_schema_name"]}.run_number_table (check_time) values ({ts})'
    )


# COMMAND ----------


def notifyworkspaceCompleted(workspaceID, completed):
    import time

    ts = time.time()
    runID = spark.sql(
        f'select max(runID) from {json_["analysis_schema_name"]}.run_number_table'
    ).collect()[0][0]
    spark.sql(
        f"""INSERT INTO {json_["analysis_schema_name"]}.workspace_run_complete (`workspace_id`,`run_id`, `completed`, `check_time`)  VALUES ({workspaceID}, {runID}, {completed}, cast({ts} as timestamp))"""
    )


# COMMAND ----------


def create_security_checks_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.security_checks")
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.security_checks (
                workspaceid string,
                id int,
                score integer,
                additional_details map<string, string>,
                run_id bigint,
                check_time timestamp,
                chk_date date GENERATED ALWAYS AS (CAST(check_time AS DATE)),
                chk_hhmm integer GENERATED ALWAYS AS (CAST(CAST(hour(check_time) as STRING) || CAST(minute(check_time) as STRING) as INTEGER))
                )
                USING DELTA
                PARTITIONED BY (chk_date)"""
    )
    # Comentarios sao metadados cosmeticos. Reaplicados a cada execucao, colidem
    # com os INSERTs dos workspaces que rodam em paralelo e derrubam a gravacao
    # com MetadataChangedException. Aplicados uma vez, na criacao, e qualquer
    # conflito e engolido.
    if not existed:
        try:
            _set_table_comment(
                schema, "security_checks",
                "Core SAT results table. One row per security check per workspace per run. "
                "Score=0 means the check passed; Score=1 means violations found. "
                "Join to security_best_practices on id for check details, and to run_number_table on run_id for run context."
            )
            _set_column_comments(schema, "security_checks", {
                "workspaceid":        "Databricks workspace ID that was analyzed",
                "id":                 "Security check ID — foreign key to security_best_practices.id",
                "score":              "0 = check passed; 1 = violation found",
                "additional_details": "Map of violation context keyed by detail type (e.g. message, workspaceId, resource names). Value is a descriptive string.",
                "run_id":             "SAT run ID — foreign key to run_number_table.runID",
                "check_time":         "Timestamp when this check was evaluated",
                "chk_date":           "Date partition derived from check_time for efficient time-range queries",
                "chk_hhmm":           "Hour and minute as integer (HHMM format) derived from check_time",
            })
        except Exception as exc:
            print(f"security_checks comments skipped: {exc}")

# COMMAND ----------


def create_account_info_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.account_info")
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.account_info (
        workspaceid string,
        name string,
        value map<string, string>,
        category string,
        run_id bigint,
        check_time timestamp,
        chk_date date GENERATED ALWAYS AS (CAST(check_time AS DATE)),
        chk_hhmm integer GENERATED ALWAYS AS (CAST(CAST(hour(check_time) as STRING) || CAST(minute(check_time) as STRING) as INTEGER))
        )
        USING DELTA
        PARTITIONED BY (chk_date)"""
    )
    # Comentarios sao metadados cosmeticos. Reaplicados a cada execucao, colidem
    # com os INSERTs dos workspaces que rodam em paralelo e derrubam a gravacao
    # com MetadataChangedException. Aplicados uma vez, na criacao, e qualquer
    # conflito e engolido.
    if not existed:
        try:
            _set_table_comment(
                schema, "account_info",
                "Workspace-level statistics and properties collected during each SAT run. Each row is one named metric for a workspace. "
                "The name column uses coded keys: AS-1=account ID, AS-2=cloud region, AS-3=deployment name, AS-4=pricing tier, "
                "AS-5=workspace ID, AS-6=workspace status, WST-1=total job count, WST-2=orphaned external job count."
            )
            _set_column_comments(schema, "account_info", {
                "workspaceid": "Databricks workspace ID this metric belongs to",
                "name":        "Coded metric key (e.g. AS-1=account ID, AS-2=cloud region, AS-4=pricing tier, WST-1=job count)",
                "value":       'JSON-encoded metric value, always in format: {"value": "<metric_value>"}',
                "category":    "Metric category: Account Stats for account-level properties, Workspace Stats for workspace-level counts",
                "run_id":      "SAT run ID when this metric was collected — foreign key to run_number_table.runID",
                "check_time":  "Timestamp when this metric was collected",
                "chk_date":    "Date partition derived from check_time",
                "chk_hhmm":    "Hour and minute as integer (HHMM) derived from check_time",
            })
        except Exception as exc:
            print(f"account_info comments skipped: {exc}")

# COMMAND ----------


def create_account_workspaces_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.account_workspaces")
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.account_workspaces (
            workspace_id string,
            deployment_url string,
            workspace_name string,
            workspace_status string,
            analysis_enabled boolean
            )
            USING DELTA"""
    )
    # Comentarios sao metadados cosmeticos. Reaplicados a cada execucao, colidem
    # com os INSERTs dos workspaces que rodam em paralelo e derrubam a gravacao
    # com MetadataChangedException. Aplicados uma vez, na criacao, e qualquer
    # conflito e engolido.
    if not existed:
        try:
            _set_table_comment(
                schema, "account_workspaces",
                "Registry of Databricks workspaces configured for SAT analysis, with high-level security posture flags set during "
                "workspace enablement. Used by Genie to answer questions like: which workspaces have SSO enabled?"
            )
            _set_column_comments(schema, "account_workspaces", {
                "workspace_id":                 "Databricks workspace ID",
                "deployment_url":               "Workspace hostname (e.g. myworkspace.cloud.databricks.com)",
                "workspace_name":               "Human-readable workspace name",
                "workspace_status":             "Current Databricks workspace status (e.g. RUNNING)",
                "analysis_enabled":             "True if SAT is configured to analyze this workspace",
            })
        except Exception as exc:
            print(f"account_workspaces comments skipped: {exc}")

# COMMAND ----------


def create_notebooks_secret_scan_results_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.notebooks_secret_scan_results")
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.notebooks_secret_scan_results (
        workspace_id STRING,
        notebook_id STRING,
        notebook_path STRING,
        notebook_name STRING,
        detector_name STRING,
        secret_sha256 STRING,
        source_file STRING,
        verified BOOLEAN,
        secrets_found INTEGER,
        run_id BIGINT,
        scan_time TIMESTAMP,
        scan_date DATE GENERATED ALWAYS AS (CAST(scan_time AS DATE)),
        scan_hhmm INTEGER GENERATED ALWAYS AS (CAST(CAST(hour(scan_time) as STRING) || CAST(minute(scan_time) as STRING) as INTEGER))
    )
    USING DELTA
    PARTITIONED BY (scan_date)
    """
    )
    # Comentarios sao metadados cosmeticos. Reaplicados a cada execucao, colidem
    # com os INSERTs dos workspaces que rodam em paralelo e derrubam a gravacao
    # com MetadataChangedException. Aplicados uma vez, na criacao, e qualquer
    # conflito e engolido.
    if not existed:
        try:
            _set_table_comment(
                schema, "notebooks_secret_scan_results",
                "TruffleHog secret scan results for Databricks notebooks. Identifies potential hardcoded secrets, API keys, "
                "and credentials in notebook source code. When secrets_found=0 and other fields are NULL, it means the "
                "workspace was scanned and no secrets were detected."
            )
            _set_column_comments(schema, "notebooks_secret_scan_results", {
                "workspace_id":  "Databricks workspace ID where the notebook resides",
                "notebook_id":   "Databricks notebook ID that was scanned",
                "notebook_path": "Full workspace path to the scanned notebook",
                "notebook_name": "Display name of the scanned notebook",
                "detector_name": "TruffleHog detector that matched (e.g. AWS, Slack, GitHub, GitLab)",
                "secret_sha256": "SHA-256 hash of the detected secret value — the actual secret is never stored",
                "source_file":   "Source file within the notebook where the secret was detected",
                "verified":      "True if TruffleHog confirmed the secret is currently active and valid",
                "secrets_found": "Count of secrets detected. 0 with NULL other fields means the workspace was clean.",
                "run_id":        "SAT secret scan run ID",
                "scan_time":     "Timestamp when the scan was performed",
                "scan_date":     "Date partition derived from scan_time",
                "scan_hhmm":     "Hour and minute as integer (HHMM) derived from scan_time",
            })
        except Exception as exc:
            print(f"notebooks_secret_scan_results comments skipped: {exc}")

def create_clusters_secret_scan_results_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.clusters_secret_scan_results")
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.clusters_secret_scan_results (
        workspace_id STRING,
        cluster_id STRING,
        cluster_name STRING,
        config_field STRING,
        config_key STRING,
        detector_name STRING,
        secret_sha256 STRING,
        source_file STRING,
        verified BOOLEAN,
        secrets_found INTEGER,
        run_id BIGINT,
        scan_time TIMESTAMP,
        scan_date DATE GENERATED ALWAYS AS (CAST(scan_time AS DATE)),
        scan_hhmm INTEGER GENERATED ALWAYS AS (CAST(CAST(hour(scan_time) as STRING) || CAST(minute(scan_time) as STRING) as INTEGER))
    )
    USING DELTA
    PARTITIONED BY (scan_date)
    """
    )
    # Comentarios sao metadados cosmeticos. Reaplicados a cada execucao, colidem
    # com os INSERTs dos workspaces que rodam em paralelo e derrubam a gravacao
    # com MetadataChangedException. Aplicados uma vez, na criacao, e qualquer
    # conflito e engolido.
    if not existed:
        try:
            _set_table_comment(
                schema, "clusters_secret_scan_results",
                "TruffleHog secret scan results for Databricks cluster configurations. Detects hardcoded secrets in Spark config, "
                "environment variables, and init scripts. When secrets_found=0 and other fields are NULL, the workspace was "
                "scanned and found clean."
            )
            _set_column_comments(schema, "clusters_secret_scan_results", {
                "workspace_id":  "Databricks workspace ID where the cluster was found",
                "cluster_id":    "Databricks cluster ID that was scanned",
                "cluster_name":  "Display name of the scanned cluster",
                "config_field":  "Cluster configuration section where the secret was found (e.g. spark_conf, env_vars)",
                "config_key":    "Specific configuration key containing the potential secret",
                "detector_name": "TruffleHog detector that matched (e.g. AWS, Slack, GitHub, GitLab)",
                "secret_sha256": "SHA-256 hash of the detected secret value — the actual secret is never stored",
                "source_file":   "Source location within the cluster config where the secret was detected",
                "verified":      "True if TruffleHog confirmed the secret is currently active and valid",
                "secrets_found": "Count of secrets detected. 0 with NULL other fields means the cluster config was clean.",
                "run_id":        "SAT secret scan run ID",
                "scan_time":     "Timestamp when the scan was performed",
                "scan_date":     "Date partition derived from scan_time",
                "scan_hhmm":     "Hour and minute as integer (HHMM) derived from scan_time",
            })
        except Exception as exc:
            print(f"clusters_secret_scan_results comments skipped: {exc}")

# COMMAND ----------


def create_scan_exception_dispositions_table():
    """Tratativas das excecoes do scan de segredos.

    A tabela de excecoes diz o que nao foi escaneado. Esta diz o que foi
    decidido a respeito: quem assumiu, ate quando, com que referencia. Sem ela,
    os mesmos objetos reaparecem todo dia sem que ninguem saiba se ha alguem
    cuidando — e o indicador vira ruido que se aprende a ignorar.

    E escrita por pessoas, nao pelo job. O SAT so le.
    """
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.scan_exception_dispositions")
    spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.scan_exception_dispositions (
        disposition_id STRING,
        escopo STRING,
        escopo_valor STRING,
        outcome STRING,
        decisao STRING,
        responsavel STRING,
        referencia_externa STRING,
        prazo DATE,
        valido_ate DATE,
        observacao STRING,
        criado_por STRING,
        criado_em TIMESTAMP,
        ativo BOOLEAN
    )
    USING DELTA
    """
    )
    if not existed:
        try:
            _set_table_comment(
                schema, "scan_exception_dispositions",
                "Tratativas das excecoes do scan de segredos: o que foi decidido sobre cada objeto, pasta ou workspace "
                "que nao pode ser escaneado. Preenchida por pessoas, nunca pelo job. A view "
                "v_secret_scan_exceptions_tratadas cruza esta tabela com as excecoes e separa o que ja tem dono do que "
                "esta pendente. Uma tratativa com valido_ate no passado deixa de valer e o item volta a aparecer como "
                "pendente — aceite de risco tem prazo, senao vira exceção permanente por esquecimento."
            )
            _set_column_comments(schema, "scan_exception_dispositions", {
                "disposition_id":     "Identificador da tratativa, livre (ex.: TRAT-2026-001)",
                "escopo":             "Granularidade: 'objeto' (casa por object_id), 'pasta' (prefixo de caminho), 'workspace', ou 'processo'/'inventario' para pontos que nao apontam para nenhum arquivo",
                "escopo_valor":       "Valor conforme o escopo: o object_id, o prefixo do caminho ou o workspace_id",
                "outcome":            "Restringe a tratativa a um motivo especifico (ex.: access_denied). NULL vale para qualquer motivo",
                "decisao":            "O que foi decidido: investigando, aguardando_acesso, em_remediacao, aceito, falso_positivo, fora_de_escopo",
                "responsavel":        "Quem assumiu a tratativa",
                "referencia_externa": "Chamado, e-mail ou solicitacao de acesso que amarra ao fluxo do banco",
                "prazo":              "Data acordada para conclusao",
                "valido_ate":         "Data em que a tratativa expira e o item volta a ser pendente. NULL nao expira — use com parcimonia",
                "observacao":         "Contexto livre",
                "criado_por":         "Quem registrou",
                "criado_em":          "Quando foi registrada",
                "ativo":              "False revoga a tratativa sem apagar o historico",
            })
        except Exception as exc:
            print(f"scan_exception_dispositions comments skipped: {exc}")


# COMMAND ----------


def create_scan_reporting_views():
    """Views de cobertura e excecoes do scan de segredos.

    O dashboard, o SQL editor e qualquer analise posterior devem ler daqui, e nao
    montar a propria juncao entre scan_discovery_stats e scan_object_events. Se a
    regra mudar, muda em um lugar so.
    """
    schema = json_["analysis_schema_name"]
    try:
        # A view de tratativas referencia a tabela de dispositions; garante que
        # exista antes, senao a view nasce quebrada num schema novo.
        create_scan_exception_dispositions_table()
        # As views abaixo leem scan_object_events e scan_discovery_stats. Num schema
        # novo essas tabelas ainda nao existem quando esta funcao roda: o registro de
        # eventos retorna cedo quando a execucao foi limpa, e a criacao ficaria para
        # depois. Sem estas duas linhas a primeira view que le scan_object_events
        # falha com TABLE_OR_VIEW_NOT_FOUND e derruba todas as seguintes.
        create_scan_object_events_table()
        create_scan_discovery_stats_table()

        # Cobertura: o funil por execucao e workspace, com o percentual efetivo.
        spark.sql(f"""
            CREATE OR REPLACE VIEW {schema}.v_secret_scan_coverage AS
            SELECT
                workspace_id,
                run_id,
                source,
                chk_date,
                discovered,
                filtered,
                eligible,
                scanned,
                skipped_empty + skipped_binary AS skipped,
                unscanned,
                CASE WHEN eligible > 0
                     THEN round(100.0 * scanned / eligible, 2)
                     ELSE NULL END AS cobertura_pct,
                status,
                check_time
            FROM (
                SELECT *, row_number() OVER (
                           PARTITION BY workspace_id, run_id, source
                           ORDER BY check_time DESC) AS rn
                FROM {schema}.scan_discovery_stats
                WHERE filter_reason IS NULL
            )
            WHERE rn = 1
        """)

        # Excecoes: um objeto por linha, com o motivo agrupado em familias.
        # access_denied e o unico que exige acao de alguem fora do SAT.
        spark.sql(f"""
            CREATE OR REPLACE VIEW {schema}.v_secret_scan_exceptions AS
            SELECT
                workspace_id,
                run_id,
                chk_date,
                object_path,
                object_id,
                outcome,
                CASE
                    WHEN outcome = 'access_denied' THEN 'Sem permissao'
                    WHEN outcome = 'stale_path' THEN 'Caminho mudou durante o scan'
                    WHEN outcome IN ('export_failed', 'unexpected_status', 'error') THEN 'Erro de leitura'
                    WHEN outcome IN ('empty', 'non_text') THEN 'Sem conteudo escaneavel'
                    ELSE 'Outro'
                END AS familia,
                detail,
                check_time
            FROM {schema}.scan_object_events
        """)

        # Excecoes cruzadas com as tratativas. Uma excecao sem tratativa valida e
        # PENDENTE; e o unico numero que exige acao. A tratativa casa por objeto,
        # por prefixo de pasta ou por workspace, e expira em valido_ate.
        spark.sql(f"""
            CREATE OR REPLACE VIEW {schema}.v_secret_scan_exceptions_tratadas AS
            SELECT
                e.workspace_id,
                e.run_id,
                e.chk_date,
                e.object_path,
                e.object_id,
                e.outcome,
                e.detail,
                d.disposition_id,
                d.decisao,
                d.responsavel,
                d.referencia_externa,
                d.prazo,
                d.valido_ate,
                CASE
                    WHEN d.disposition_id IS NULL THEN 'PENDENTE'
                    WHEN d.decisao IS NULL OR trim(d.decisao) = '' THEN 'AGUARDANDO DECISAO'
                    WHEN d.valido_ate IS NOT NULL AND d.valido_ate < current_date() THEN 'TRATATIVA VENCIDA'
                    WHEN d.prazo IS NOT NULL AND d.prazo < current_date()
                         AND d.decisao IN ('investigando', 'aguardando_acesso', 'em_remediacao') THEN 'PRAZO ESTOURADO'
                    ELSE 'TRATADO'
                END AS situacao
            FROM {schema}.scan_object_events e
            LEFT JOIN {schema}.scan_exception_dispositions d
              ON d.ativo = true
             AND (d.outcome IS NULL OR d.outcome = e.outcome)
             AND (
                    (d.escopo = 'objeto'    AND d.escopo_valor = e.object_id)
                 OR (d.escopo = 'pasta'     AND e.object_path LIKE concat(d.escopo_valor, '%'))
                 OR (d.escopo = 'workspace' AND d.escopo_valor = e.workspace_id)
                 )
        """)

        # Completude por execucao e por workspace. Substitui a falha do job: a
        # execucao parcial nao para mais o pipeline, ela fica registrada aqui.
        # O numero que exige acao nao e "unscanned > 0" — esse dispara em cima de
        # excecao ja conhecida e vira ruido. E "excecoes_pendentes > 0": objeto
        # nao lido que ninguem decidiu o que fazer. Evidencia perdida
        # (findings_unwritten) e categoria a parte e mais grave: ali o segredo foi
        # encontrado e o registro se perdeu, o que nenhuma tratativa cobre.
        # SEM RASTRO existe porque a alternativa era mentir: unscanned maior que
        # zero sem nenhum evento correspondente em scan_object_events nao prova
        # tratativa, prova que o registro do evento falhou. Chamar isso de TRATADO
        # seria trocar um falso positivo por um falso negativo, que e pior.
        # EXECUCAO NAO CONCLUIDA vem da linha de abertura que o scan grava antes
        # de comecar. A view nao distingue "rodando agora" de "morreu no meio" —
        # ninguem consegue, olhando so a tabela. Quem separa os dois e o relogio:
        # execucao aberta e nao fechada depois do job terminar foi interrompida.
        # Sem essa linha, a execucao que morre no meio nao deixa registro nenhum,
        # e ausencia de linha e o unico sinal que ninguem ve.
        spark.sql(f"""
            CREATE OR REPLACE VIEW {schema}.v_secret_scan_completude AS
            SELECT
                s.workspace_id,
                s.run_id,
                s.source,
                s.chk_date,
                s.check_time,
                s.eligible,
                s.scanned,
                s.unscanned,
                s.findings_attempted,
                s.findings_unwritten,
                CASE WHEN s.eligible > 0
                     THEN round(100.0 * s.scanned / s.eligible, 2)
                     ELSE NULL END AS cobertura_pct,
                CASE
                    WHEN s.status IS NOT NULL THEN s.status
                    WHEN s.unscanned > 0 OR coalesce(s.findings_unwritten, 0) > 0 THEN 'INCOMPLETO'
                    ELSE 'COMPLETO'
                END AS status,
                (SELECT count(DISTINCT t.object_id)
                   FROM {schema}.v_secret_scan_exceptions_tratadas t
                  WHERE t.workspace_id = s.workspace_id
                    AND t.run_id = s.run_id
                    AND t.outcome IN ('access_denied', 'export_failed', 'unexpected_status', 'error')
                    AND t.situacao = 'PENDENTE') AS excecoes_pendentes,
                (SELECT count(DISTINCT t.object_id)
                   FROM {schema}.v_secret_scan_exceptions_tratadas t
                  WHERE t.workspace_id = s.workspace_id
                    AND t.run_id = s.run_id
                    AND t.outcome IN ('access_denied', 'export_failed', 'unexpected_status', 'error')
                    AND t.situacao <> 'PENDENTE') AS excecoes_com_tratativa,
                CASE
                    WHEN s.status = 'EM EXECUCAO' THEN 'EXECUCAO NAO CONCLUIDA'
                    WHEN coalesce(s.findings_unwritten, 0) > 0 THEN 'EVIDENCIA PERDIDA'
                    WHEN (SELECT count(DISTINCT t.object_id)
                            FROM {schema}.v_secret_scan_exceptions_tratadas t
                           WHERE t.workspace_id = s.workspace_id
                             AND t.run_id = s.run_id
                             AND t.outcome IN ('access_denied', 'export_failed', 'unexpected_status', 'error')
                             AND t.situacao = 'PENDENTE') > 0 THEN 'INCOMPLETO PENDENTE'
                    WHEN s.unscanned > 0
                         AND (SELECT count(DISTINCT t.object_id)
                                FROM {schema}.v_secret_scan_exceptions_tratadas t
                               WHERE t.workspace_id = s.workspace_id
                                 AND t.run_id = s.run_id
                                 AND t.outcome IN ('access_denied', 'export_failed',
                                                   'unexpected_status', 'error')) = 0
                         THEN 'INCOMPLETO SEM RASTRO'
                    WHEN s.unscanned > 0 THEN 'INCOMPLETO TRATADO'
                    ELSE 'OK'
                END AS veredito
            FROM (
                SELECT *, row_number() OVER (
                           PARTITION BY workspace_id, run_id, source
                           ORDER BY check_time DESC) AS rn
                FROM {schema}.scan_discovery_stats
                WHERE filter_reason IS NULL
            ) s
            WHERE s.rn = 1
        """)

        # Os pontos em si, independentemente de casarem com objetos. Pontos de
        # processo e de inventario nao apontam para nenhum arquivo, mas precisam
        # aparecer na mesma lista para a conversa com o cliente ser uma so.
        spark.sql(f"""
            CREATE OR REPLACE VIEW {schema}.v_pontos_tratativa AS
            SELECT
                d.disposition_id,
                d.escopo,
                d.escopo_valor,
                d.outcome,
                d.decisao,
                d.responsavel,
                d.referencia_externa,
                d.prazo,
                d.valido_ate,
                d.observacao,
                CASE
                    WHEN d.decisao IS NULL OR trim(d.decisao) = '' THEN 'AGUARDANDO DECISAO'
                    WHEN d.valido_ate IS NOT NULL AND d.valido_ate < current_date() THEN 'TRATATIVA VENCIDA'
                    WHEN d.prazo IS NOT NULL AND d.prazo < current_date()
                         AND d.decisao IN ('investigando', 'aguardando_acesso', 'em_remediacao') THEN 'PRAZO ESTOURADO'
                    ELSE 'TRATADO'
                END AS situacao,
                (SELECT count(*) FROM {schema}.scan_object_events e
                  WHERE (d.outcome IS NULL OR d.outcome = e.outcome)
                    AND (
                          (d.escopo = 'objeto'    AND d.escopo_valor = e.object_id)
                       OR (d.escopo = 'pasta'     AND e.object_path LIKE concat(d.escopo_valor, '%'))
                       OR (d.escopo = 'workspace' AND d.escopo_valor = e.workspace_id)
                        )
                ) AS objetos_afetados,
                d.criado_por,
                d.criado_em
            FROM {schema}.scan_exception_dispositions d
            WHERE d.ativo = true
        """)

        # Recorrencia: separa o que falha sempre do que falhou uma vez. E aqui que
        # mora o sinal — problema cronico versus evento isolado.
        spark.sql(f"""
            CREATE OR REPLACE VIEW {schema}.v_secret_scan_exceptions_recorrentes AS
            SELECT
                workspace_id,
                object_id,
                max(object_path) AS ultimo_caminho,
                outcome,
                count(DISTINCT chk_date) AS dias_afetados,
                min(chk_date) AS primeira_ocorrencia,
                max(chk_date) AS ultima_ocorrencia
            FROM {schema}.scan_object_events
            GROUP BY workspace_id, object_id, outcome
        """)
    except Exception as exc:
        print(f"scan reporting views skipped: {exc}")


# COMMAND ----------


def create_scan_object_events_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.scan_object_events")
    spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.scan_object_events (
        workspace_id STRING,
        run_id BIGINT,
        source STRING,
        object_path STRING,
        object_id STRING,
        outcome STRING,
        detail STRING,
        check_time TIMESTAMP,
        chk_date DATE GENERATED ALWAYS AS (CAST(check_time AS DATE))
    )
    USING DELTA
    PARTITIONED BY (chk_date)
    """
    )
    if not existed:
        try:
            _set_table_comment(
                schema, "scan_object_events",
                "Uma linha por objeto que a analise de segredos nao conseguiu escanear, com o motivo. Complementa "
                "scan_discovery_stats, que traz apenas os totais: aqui esta o caminho de cada objeto, o que permite "
                "acompanhar o mesmo notebook entre execucoes e ver se o problema persiste ou se resolveu sozinho. "
                "Objetos escaneados com sucesso nao aparecem, e os descartados por regra de filtro entram apenas como "
                "contagem em scan_discovery_stats."
            )
            _set_column_comments(schema, "scan_object_events", {
                "workspace_id": "Databricks workspace ID onde o objeto estava",
                "run_id":       "ID da execucao do SAT — chave estrangeira para run_number_table.runID",
                "source":       "Tarefa que registrou o evento (ex.: notebook_secret_scan)",
                "object_path":  "Caminho do objeto no workspace, como visto na descoberta",
                "object_id":    "ID do objeto no Databricks, estavel mesmo quando o caminho muda",
                "outcome":      "Motivo de nao ter sido escaneado: stale_path (caminho mudou entre descoberta e leitura), access_denied (HTTP 403), export_failed, empty, non_text, unexpected_status, error",
                "detail":       "Detalhe do motivo, quando houver",
                "check_time":   "Momento do registro",
                "chk_date":     "Particao de data derivada de check_time",
            })
        except Exception as exc:
            print(f"scan_object_events comments skipped: {exc}")


# COMMAND ----------


def create_scan_discovery_stats_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.scan_discovery_stats")
    spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.scan_discovery_stats (
        workspace_id STRING,
        run_id BIGINT,
        source STRING,
        discovered INT,
        filtered INT,
        eligible INT,
        scanned INT,
        skipped_empty INT,
        skipped_binary INT,
        unscanned INT,
        findings_attempted INT,
        findings_unwritten INT,
        status STRING,
        filter_reason STRING,
        filter_count INT,
        check_time TIMESTAMP,
        chk_date DATE GENERATED ALWAYS AS (CAST(check_time AS DATE))
    )
    USING DELTA
    PARTITIONED BY (chk_date)
    """
    )

    # Tabela criada antes de a completude virar dado e trazida para a frente no
    # lugar. Linhas antigas ficam com status NULL, que a view le como
    # DESCONHECIDO: nao da para afirmar completude de uma execucao que nunca
    # gravou o veredito.
    if existed:
        try:
            cols = {f.name for f in spark.table(f"{schema}.scan_discovery_stats").schema.fields}
            faltando = [
                (nome, tipo) for nome, tipo in
                (("findings_attempted", "INT"), ("findings_unwritten", "INT"), ("status", "STRING"))
                if nome not in cols
            ]
            if faltando:
                defs = ", ".join(f"{nome} {tipo}" for nome, tipo in faltando)
                spark.sql(f"ALTER TABLE {schema}.scan_discovery_stats ADD COLUMNS ({defs})")
        except Exception as exc:
            print(f"scan_discovery_stats migration skipped: {exc}")

    if not existed:
        try:
            _set_table_comment(
                schema, "scan_discovery_stats",
                "Funil de descoberta do scanner de segredos, por execucao e por workspace. Mostra quantos objetos a "
                "descoberta retornou, quantos foram descartados antes do scan por nao serem codigo-fonte, quantos "
                "seguiram para analise e quantos de fato foram lidos. A linha com filter_reason NULL e o resumo do "
                "workspace; as demais detalham o motivo de cada descarte (extensao ou trecho de caminho)."
            )
            _set_column_comments(schema, "scan_discovery_stats", {
                "workspace_id":   "Databricks workspace ID analisado nesta execucao",
                "run_id":         "ID da execucao do SAT — chave estrangeira para run_number_table.runID",
                "source":         "Tarefa que registrou o funil (ex.: notebook_secret_scan)",
                "discovered":     "Objetos que a descoberta retornou, antes de qualquer filtro",
                "filtered":       "Objetos descartados antes do scan por nao serem codigo-fonte (dados, binarios, internos de Git)",
                "eligible":       "Objetos que seguiram para o scan: discovered menos filtered",
                "scanned":        "Objetos efetivamente lidos e analisados pelo TruffleHog",
                "skipped_empty":  "Objetos elegiveis que vieram sem conteudo no export",
                "skipped_binary": "Objetos elegiveis cujo conteudo nao decodificou como texto",
                "unscanned":      "Elegiveis que nao foram lidos por permissao, throttling ou falha de export. Maior que zero marca a execucao como INCOMPLETA, sem reprovar o job",
                "findings_attempted": "Achados que o scan tentou gravar na tabela de resultados",
                "findings_unwritten": "Achados que falharam ao gravar mesmo apos os retries. Maior que zero significa evidencia perdida",
                "status":         "Veredito de completude da execucao no workspace: COMPLETO ou INCOMPLETO. Registrado como dado, nao como falha do job",
                "filter_reason":  "Motivo do descarte: extensao (ex.: .parquet) ou trecho de caminho (ex.: /.git/). NULL na linha de resumo",
                "filter_count":   "Quantidade descartada por esse motivo. NULL na linha de resumo",
                "check_time":     "Momento do registro",
                "chk_date":       "Particao de data derivada de check_time",
            })
        except Exception as exc:
            print(f"scan_discovery_stats comments skipped: {exc}")


# COMMAND ----------


def create_network_diagnostics_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.network_diagnostics")
    spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.network_diagnostics (
        workspace_id STRING,
        workspace_url STRING,
        run_id BIGINT,
        source STRING,
        endpoint STRING,
        reachable BOOLEAN,
        http_code INTEGER,
        latency_ms DOUBLE,
        detail STRING,
        check_time TIMESTAMP,
        chk_date DATE GENERATED ALWAYS AS (CAST(check_time AS DATE))
    )
    USING DELTA
    PARTITIONED BY (chk_date)
    """
    )

    # A table created before run_id existed is brought forward in place; old
    # rows keep a NULL run_id, which the dedup treats as "unknown run".
    migrated = False
    if existed:
        try:
            cols = {f.name for f in spark.table(f"{schema}.network_diagnostics").schema.fields}
            if "run_id" not in cols:
                spark.sql(f"ALTER TABLE {schema}.network_diagnostics ADD COLUMNS (run_id BIGINT)")
                migrated = True
        except Exception as exc:
            print(f"network_diagnostics migration skipped: {exc}")

    # Two scan tasks can reach this point at the same time. Comments are
    # cosmetic metadata, so a concurrent COMMENT/ALTER losing the race must
    # never abort the caller: they are attempted on first creation or right
    # after a schema migration, and any conflict is swallowed.
    if not existed or migrated:
        try:
            _set_table_comment(
                schema, "network_diagnostics",
                "Egress connectivity checks recorded by SAT jobs at the start of each run. Each row is one probe to an "
                "external endpoint the job depends on, issued from the workspace that hosts the SAT cluster. Use to see "
                "whether the endpoints SAT needs are reachable and how that changes over time. Note this measures the "
                "egress of the SAT workspace only, not of each analyzed workspace."
            )
            _set_column_comments(schema, "network_diagnostics", {
                "workspace_id":  "Databricks workspace ID this SAT task was analyzing when the probe ran — the target, not the origin of the request",
                "workspace_url": "Host of the workspace the probe was issued from, i.e. where the SAT cluster runs",
                "run_id":        "SAT run ID the probe belongs to — foreign key to run_number_table.runID; NULL for rows written before this column existed",
                "source":        "SAT task that recorded the probe (e.g. notebook_secret_scan, cluster_secrets_scan)",
                "endpoint":      "External endpoint probed (e.g. https://github.com)",
                "reachable":     "True if the endpoint answered an HTTP request within the timeout. A 404 still counts as reachable: the host answered",
                "http_code":     "HTTP status code returned by the endpoint, NULL when the connection failed",
                "latency_ms":    "Round-trip time of the probe in milliseconds",
                "detail":        "Error detail when the probe failed, empty when it succeeded",
                "check_time":    "Timestamp when the probe ran",
                "chk_date":      "Date partition derived from check_time",
            })
        except Exception as exc:
            print(f"network_diagnostics comments skipped: {exc}")


# COMMAND ----------


def create_workspace_run_complete_table():
    schema = json_["analysis_schema_name"]
    existed = spark.catalog.tableExists(f"{schema}.workspace_run_complete")
    df = spark.sql(
        f"""CREATE TABLE IF NOT EXISTS {schema}.workspace_run_complete(
                    workspace_id string,
                    run_id bigint,
                    completed boolean,
                    check_time timestamp,
                    chk_date date GENERATED ALWAYS AS (CAST(check_time AS DATE))
                    )
                    USING DELTA"""
    )
    # Comentarios sao metadados cosmeticos. Reaplicados a cada execucao, colidem
    # com os INSERTs dos workspaces que rodam em paralelo e derrubam a gravacao
    # com MetadataChangedException. Aplicados uma vez, na criacao, e qualquer
    # conflito e engolido.
    if not existed:
        try:
            _set_table_comment(
                schema, "workspace_run_complete",
                "Tracks per-workspace completion status for each SAT run. Use to identify which workspaces completed "
                "successfully and which failed in a given run. Join to run_number_table on run_id."
            )
            _set_column_comments(schema, "workspace_run_complete", {
                "workspace_id": "Databricks workspace ID",
                "run_id":       "SAT run ID — foreign key to run_number_table.runID",
                "completed":    "True if the workspace analysis completed successfully in this run",
                "check_time":   "Timestamp when the workspace analysis completed",
                "chk_date":     "Date partition derived from check_time",
            })
        except Exception as exc:
            print(f"workspace_run_complete comments skipped: {exc}")

# COMMAND ----------


def _set_table_comment(schema, table, comment):
    safe = comment.replace("'", "''")
    spark.sql(f"COMMENT ON TABLE {schema}.`{table}` IS '{safe}'")


def _set_column_comments(schema, table, col_comments):
    for col, comment in col_comments.items():
        safe = comment.replace("'", "''")
        spark.sql(f"ALTER TABLE {schema}.`{table}` ALTER COLUMN `{col}` COMMENT '{safe}'")


# COMMAND ----------

def generateGCPWSToken(deployment_url, cred_file_path,target_principal):
    from google.oauth2 import service_account
    import gcsfs
    import json 
    gcp_accounts_url = 'https://accounts.gcp.databricks.com'
    target_scopes = [deployment_url]
    print(target_scopes)
    # Reading gcs files with gcsfs
    gcs_file_system = gcsfs.GCSFileSystem(project="gcp_project_name")
    gcs_json_path = cred_file_path
    with gcs_file_system.open(gcs_json_path) as f:
      json_dict = json.load(f)
      key = json.dumps(json_dict) 
    source_credentials = service_account.Credentials.from_service_account_info(json_dict,scopes=target_scopes)
    from google.auth import impersonated_credentials
    from google.auth.transport.requests import AuthorizedSession

    target_credentials = impersonated_credentials.Credentials(
      source_credentials=source_credentials,
      target_principal=target_principal,
      target_scopes = target_scopes,
      lifetime=36000)

    creds = impersonated_credentials.IDTokenCredentials(
                                      target_credentials,
                                      target_audience=deployment_url,
                                      include_email=True)

    authed_session = AuthorizedSession(creds)
    resp = authed_session.get(gcp_accounts_url)
    return creds.token
    

# COMMAND ----------

from pyspark.sql import DataFrame
def isEmpty(df: DataFrame):
    return len(df.take(1))==0

# COMMAND ----------

def process_json_schema(df):
    from pyspark.sql.functions import schema_of_json, col, from_json,collect_set,explode
    #df_with_schemas = df.select(explode(collect_set(schema_of_json(col("json_string")))).alias("schema"))
    df_with_schemas = df.select(schema_of_json(col("json_string")).alias("schema")).distinct()

    from pyspark.sql.types import StructType
    from collections import OrderedDict

    all_fields = OrderedDict()

    for row in df_with_schemas.select("schema").collect():
        schema_str = row.schema
        # Remove the outer 'STRUCT<' and '>' 
        inner_schema = schema_str[7:-1]
        schema = StructType.fromDDL(inner_schema)        
        for field in schema.fields:
            all_fields[field.name] = field
    final_struct = StructType(list(all_fields.values()))
    return final_struct

# COMMAND ----------

# For testing
JSONLOCALTESTA = '{"account_id": "", "sql_warehouse_id": "", "verbosity": "info", "master_name_scope": "sat_scope", "master_name_key": "user", "master_pwd_scope": "sat_scope", "master_pwd_key": "pass", "workspace_pat_scope": "sat_scope", "workspace_pat_token_prefix": "sat_token", "dashboard_id": "317f4809-8d9d-4956-a79a-6eee51412217", "dashboard_folder": "../../dashboards/", "dashboard_tag": "SAT", "use_mastercreds": true, "url": "https://satanalysis.cloud.databricks.com", "workspace_id": "2657683783405196", "cloud_type": "aws", "clusterid": "1115-184042-ntswg7ll"}'

# COMMAND ----------

JSONLOCALTESTB = '{"account_id": "", "sql_warehouse_id": "4a936419ee9b9d68",  "verbosity": "info", "master_name_scope": "sat_scope", "master_name_key": "user", "master_pwd_scope": "sat_scope", "master_pwd_key": "pass", "workspace_pat_scope": "sat_scope", "workspace_pat_token_prefix": "sat_token", "dashboard_id": "317f4809-8d9d-4956-a79a-6eee51412217", "dashboard_folder": "../../dashboards/", "dashboard_tag": "SAT", "use_mastercreds": true, "subscription_id": "", "tenant_id": "", "client_id": "", "client_secret": "", "generate_pat_tokens": false, "url": "https://adb-83xxx7.17.azuredatabricks.net", "workspace_id": "83xxxx7", "clusterid": "0105-242242-ir40aiai", "cloud_type":"azure"}'
