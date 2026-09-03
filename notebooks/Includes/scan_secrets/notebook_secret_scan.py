# Databricks notebook source
# MAGIC %md
# MAGIC # TruffleHog Secret Scanner for Databricks Notebooks
# MAGIC
# MAGIC ## Overview
# MAGIC This notebook scans Databricks workspace notebooks for exposed secrets using TruffleHog. It integrates with the Security Analysis Tool (SAT) to provide comprehensive secret detection across your Databricks environment.
# MAGIC
# MAGIC ## Features
# MAGIC - Scans all notebooks modified within a specified timeframe
# MAGIC - Uses custom detectors for Databricks-specific tokens
# MAGIC - Excludes built-in Databricks tokens to reduce false positives  
# MAGIC - Provides detailed reporting with SHA-256 hashed secrets for security
# MAGIC - Handles pagination for large workspaces
# MAGIC - Includes proper error handling and rate limiting
# MAGIC
# MAGIC ## Prerequisites
# MAGIC - Databricks workspace with appropriate permissions
# MAGIC - Access to install packages and run shell commands
# MAGIC - Valid Databricks API token (automatically extracted from notebook context)
# MAGIC
# MAGIC ---

# COMMAND ----------

# MAGIC %run ../install_sat_sdk

# COMMAND ----------

import time
start_time = time.time()

# COMMAND ----------

# MAGIC %run ../../Utils/common

# COMMAND ----------

test=False #local testing
if test:
    jsonstr = JSONLOCALTEST
else:
    jsonstr = dbutils.widgets.get('json_')

# COMMAND ----------

import json
if not jsonstr:
    print('cannot run notebook by itself')
    dbutils.notebook.exit('cannot run notebook by itself')
else:
    json_ = json.loads(jsonstr)

# COMMAND ----------


from core.logging_utils import LoggingUtils

LoggingUtils.set_logger_level(LoggingUtils.get_log_level(json_["verbosity"]))
loggr = LoggingUtils.get_logger()

# COMMAND ----------

hostname = dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiUrl().getOrElse(None)
cloud_type = getCloudType(hostname)

# COMMAND ----------

import requests
from core import  parser as pars
from core.dbclient import SatDBClient

if cloud_type =='azure': # use client secret
  client_secret = dbutils.secrets.get(json_['master_name_scope'], json_["client_secret_key"])
  json_.update({'token':'dapijedi', 'client_secret': client_secret})
elif (cloud_type =='aws' and json_['use_sp_auth'].lower() == 'true'):  
  client_secret = dbutils.secrets.get(json_['master_name_scope'], json_["client_secret_key"])
  json_.update({'token':'dapijedi', 'client_secret': client_secret})
  mastername =' ' # this will not be present when using SPs
  masterpwd = ' '  # we still need to send empty user/pwd.
  json_.update({'token':'dapijedi', 'mastername':mastername, 'masterpwd':masterpwd})
else: # Populate the master key for the Accounts API
  client_secret = dbutils.secrets.get(json_['master_name_scope'], json_["client_secret_key"])
  json_.update({'token':'dapijedi', 'client_secret': client_secret})
  mastername = ' '
  masterpwd = ' '
  #mastername = dbutils.secrets.get(json_['master_name_scope'], json_['master_name_key'])
  #masterpwd = dbutils.secrets.get(json_['master_pwd_scope'], json_['master_pwd_key'])
  json_.update({'token':'dapijedi', 'mastername':mastername, 'masterpwd':masterpwd})

db_client = SatDBClient(json_)


# COMMAND ----------

# Egress connectivity check: probe the external endpoints this scan depends on
# and append the results to {analysis_schema}.network_diagnostics. Failures
# here never block the scan; the goal is a persistent record of whether the
# endpoints SAT needs are reachable from the workspace hosting its cluster,
# and how that changes over time. Recorded once per run per scan task.

NETWORK_DIAG_ENDPOINTS = [
    "https://github.com",
    "https://raw.githubusercontent.com",
    "https://objects.githubusercontent.com",
]


def record_network_diagnostics(source: str) -> None:
    try:
        create_network_diagnostics_table()
        schema = json_["analysis_schema_name"]

        # The probe leaves from the workspace hosting the SAT cluster, which is
        # not the workspace being analyzed. apiUrl() returns the regional Azure
        # endpoint and identifies nothing, so the cluster's own workspace host
        # is used instead.
        try:
            probe_host = spark.conf.get("spark.databricks.workspaceUrl")
        except Exception:
            probe_host = str(hostname or "")

        raw_run_id = json_.get("run_id")
        try:
            run_id_sql = str(int(raw_run_id))
        except (TypeError, ValueError):
            run_id_sql = "NULL"

        # One probe set per job run per source: the scan notebook is invoked
        # once per analyzed workspace, and every invocation would otherwise
        # re-measure the same single egress path.
        if run_id_sql != "NULL":
            already = spark.sql(
                f"""SELECT 1 FROM {schema}.network_diagnostics
                    WHERE run_id = {run_id_sql} AND source = '{source}' LIMIT 1"""
            ).take(1)
            if already:
                print(f"Network diagnostics already recorded for run {run_id_sql} ({source})")
                return

        ws_id = str(json_.get("workspace_id", "unknown")).replace("'", "''")
        ws_url = str(probe_host).replace("'", "''")
        for endpoint in NETWORK_DIAG_ENDPOINTS:
            probe_start = time.time()
            try:
                resp = requests.head(endpoint, timeout=10, allow_redirects=True)
                latency = round((time.time() - probe_start) * 1000.0, 1)
                code, ok, detail = str(resp.status_code), "true", ""
            except Exception as exc:
                latency = round((time.time() - probe_start) * 1000.0, 1)
                code, ok = "NULL", "false"
                detail = str(exc)[:500].replace("'", "''")
            spark.sql(
                f"""INSERT INTO {schema}.network_diagnostics
                    (workspace_id, workspace_url, run_id, source, endpoint, reachable, http_code, latency_ms, detail, check_time)
                    VALUES ('{ws_id}', '{ws_url}', {run_id_sql}, '{source}', '{endpoint}',
                            {ok}, {code}, {latency}, '{detail}', current_timestamp())"""
            )
        print(f"Network diagnostics recorded for {len(NETWORK_DIAG_ENDPOINTS)} endpoint(s) from {probe_host}")
    except Exception as exc:
        print(f"Network diagnostics skipped: {exc}")

record_network_diagnostics("notebook_secret_scan")

# COMMAND ----------

# Offline TruffleHog: when a pre-provisioned binary exists in the workspace
# lib/ folder, stage it to /tmp before the install cell so no download is
# needed. The install cell below is idempotent and skips the download when
# /tmp/trufflehog already exists.
import os as _os
import shutil as _shutil
import stat as _stat

try:
    _lib_trufflehog = f"{getLibPath()}/trufflehog"
    if _os.path.exists("/tmp/trufflehog"):
        print("TruffleHog already present at /tmp/trufflehog")
    elif _os.path.exists(_lib_trufflehog):
        _shutil.copyfile(_lib_trufflehog, "/tmp/trufflehog")
        _os.chmod("/tmp/trufflehog", _os.stat("/tmp/trufflehog").st_mode | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
        print(f"TruffleHog staged from {_lib_trufflehog} to /tmp/trufflehog")
    else:
        print(f"No pre-provisioned TruffleHog at {_lib_trufflehog}; the install cell will download it")
except Exception as exc:
    print(f"TruffleHog pre-stage skipped: {exc}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Install Dependencies and Setup TruffleHog
# MAGIC
# MAGIC This cell installs required Python packages and downloads TruffleHog binary.

# COMMAND ----------

# MAGIC %sh
# MAGIC # Install required Python packages
# MAGIC # Skip on serverless: requests and pyyaml are pre-installed; outbound PyPI access is blocked.
# MAGIC if [[ "$DATABRICKS_RUNTIME_VERSION" == client* ]]; then
# MAGIC     echo "Serverless runtime detected - requests and pyyaml are pre-installed, skipping pip install"
# MAGIC else
# MAGIC     pip install requests==2.32.3 PyYAML==6.0.2
# MAGIC fi
# MAGIC
# MAGIC # Check if TruffleHog is already installed (idempotent installation)
# MAGIC if [ -f /tmp/trufflehog ]; then
# MAGIC     echo "TruffleHog already installed at /tmp/trufflehog"
# MAGIC     echo "Skipping installation (already exists)"
# MAGIC else
# MAGIC     # Download and install TruffleHog binary to /tmp directory
# MAGIC     # Pinned to a tagged release to prevent supply-chain tampering via the
# MAGIC     # mutable main branch. Bump TRUFFLEHOG_VERSION to upgrade.
# MAGIC     TRUFFLEHOG_VERSION=v3.94.3
# MAGIC     echo "Installing TruffleHog ${TRUFFLEHOG_VERSION}..."
# MAGIC     if curl -sSfL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/refs/tags/${TRUFFLEHOG_VERSION}/scripts/install.sh" | sh -s -- -b /tmp "${TRUFFLEHOG_VERSION}"; then
# MAGIC         if [ -f /tmp/trufflehog ]; then
# MAGIC             echo "Setup completed successfully!"
# MAGIC             echo "TruffleHog binary location: /tmp/trufflehog"
# MAGIC             echo "Configuration will be loaded from: /Workspace/Repos/.../configs/trufflehog_detectors.yaml"
# MAGIC         else
# MAGIC             echo "ERROR: TruffleHog binary not found after installation!"
# MAGIC             echo "Please verify network access and try again."
# MAGIC             exit 1
# MAGIC         fi
# MAGIC     else
# MAGIC         echo "=========================================="
# MAGIC         echo "ERROR: Failed to download TruffleHog"
# MAGIC         echo "=========================================="
# MAGIC         echo ""
# MAGIC         echo "The TruffleHog security scanner could not be downloaded from:"
# MAGIC         echo "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
# MAGIC         echo ""
# MAGIC         echo "Possible causes:"
# MAGIC         echo "  1. Network connectivity issues"
# MAGIC         echo "  2. Firewall or proxy blocking external downloads"
# MAGIC         echo "  3. GitHub.com access is restricted in your environment"
# MAGIC         echo ""
# MAGIC         echo "ACTION REQUIRED:"
# MAGIC         echo "Please contact your IT/Security team to allowlist access to:"
# MAGIC         echo "  - raw.githubusercontent.com"
# MAGIC         echo "  - github.com/trufflesecurity"
# MAGIC         echo ""
# MAGIC         echo "Alternatively, you may need to configure a proxy or use an"
# MAGIC         echo "internal mirror of the TruffleHog installation package."
# MAGIC         echo "=========================================="
# MAGIC         exit 1
# MAGIC     fi
# MAGIC fi
# MAGIC
# MAGIC echo "✅ TruffleHog setup verified!"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Configuration and Authentication
# MAGIC
# MAGIC This cell sets up configuration constants and extracts Databricks authentication context.

# COMMAND ----------

# Import required libraries
import os
import requests
import time
import json
import base64
import subprocess
import hashlib
import logging
import shutil
import yaml
import tempfile
import concurrent.futures
import random
from datetime import timedelta, datetime
from urllib.parse import quote
from typing import Dict, List, Optional, Any, Tuple

# Configure logging for better debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Objects that were discovered but hold nothing to scan: empty files and
# binaries such as images. They are not scan failures and must not count
# toward the incomplete-scan check.
skip_stats = {"empty": 0, "non_text": 0}

# Objeto que existia na descoberta e cujo caminho nao vale mais na hora da
# leitura, por ter sido movido ou removido no intervalo. Nao e falha do SAT nem
# de acesso: o alvo mudou de lugar. Contado a parte para nao reprovar a execucao.
stale_stats = {"stale_path": 0}


# --- Filtro de descoberta -------------------------------------------------
# A descoberta por workspace/list e por unified-search devolve todo objeto de
# uma pasta, nao apenas codigo-fonte: arquivos de dado (.parquet), o object
# store interno do Git (.git/objects) e binarios diversos entram na lista.
# Nenhum deles tem texto escaneavel, e a API de export recusa boa parte com
# erro em vez de conteudo vazio — o que os fazia cair no balde de falha e
# disparar INCOMPLETE SCAN por motivo errado.
#
# Filtrar antes de exportar tem dois efeitos: o portao de falha volta a medir
# so o que importa, e o job para de gastar chamadas de API com arquivos que
# jamais teriam conteudo util.

NON_SOURCE_PATH_PARTS = (
    "/.git/",          # object store, refs e packs do Git
    "/_delta_log/",    # log de transacao do Delta
    "/__pycache__/",
    "/.ipynb_checkpoints/",
)

NON_SOURCE_EXTENSIONS = (
    # dados
    ".parquet", ".avro", ".orc", ".crc", ".snappy",
    # internos do Git
    ".pack", ".idx", ".rev", ".promisor", ".bitmap",
    # binarios e empacotados
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".jar", ".war", ".whl", ".egg",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".class", ".pyc", ".pyd",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt",
)

# Contagem do que foi filtrado, por motivo. Zerada a cada execucao do fluxo.
discovery_stats = {"discovered": 0, "eligible": 0}
filtered_reasons: Dict[str, int] = {}

# Registro por objeto do que nao foi escaneado, com o motivo. Contagem agregada
# responde "quanto"; isto responde "qual e por que", que e o que permite
# comparar execucoes: o notebook X falhou ontem por Y e passou hoje.
# Cada item: (caminho, object_id, desfecho, detalhe).
object_events: List[tuple] = []


# Ultima mensagem de erro devolvida pela API por caminho. Preenchida em
# check_notebook_status e consumida no registro do evento, para que `detail`
# carregue a explicacao do servidor e nao uma frase nossa.
_last_api_error: Dict[str, str] = {}


def record_object_event(path: str, object_id: str, outcome: str, detail: str = "") -> None:
    if not detail:
        detail = _last_api_error.pop(path, "") or ""
    object_events.append((path or "", str(object_id or ""), outcome, detail or ""))


def classify_non_source(path: str) -> Optional[str]:
    """Devolve o motivo do descarte, ou None quando o objeto e elegivel."""
    if not path:
        return None
    lowered = path.lower()
    for part in NON_SOURCE_PATH_PARTS:
        if part in lowered:
            return part
    for ext in NON_SOURCE_EXTENSIONS:
        if lowered.endswith(ext):
            return ext
    return None


def filter_non_source(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Separa os objetos elegiveis e contabiliza os descartados por motivo.

    `items` chega no formato {id, name, workspace_path}, o mesmo que o
    processador de lote consome.
    """
    eligible = []
    for item in items:
        parent = item.get("workspace_path", "") or ""
        name = item.get("name", "") or ""
        full_path = f"{parent}/{name}" if parent else name
        reason = classify_non_source(full_path)
        if reason is None:
            eligible.append(item)
        else:
            filtered_reasons[reason] = filtered_reasons.get(reason, 0) + 1

    discovery_stats["discovered"] += len(items)
    discovery_stats["eligible"] += len(eligible)
    return eligible


def _default_config() -> Dict[str, Any]:
    """Built-in fallback used only when the shipped config can't be loaded."""
    return {
        "detectors": [
            {"name": "DkeaToken", "keywords": ["dkea"], "regex": {"id": "(?i)\\b(dkea[a-h0-9]{32})"}},
            {"name": "DapiToken", "keywords": ["dapi"], "regex": {"id": "(?i)\\b(dapi[a-h0-9]{32})"}},
            {"name": "DoseToken", "keywords": ["dose"], "regex": {"id": "(?i)\\b(dose[a-h0-9]{32})"}}
        ],
        "settings": {
            "excluded_detectors": ["DatabricksToken"],
            "rate_limiting": {"api_sleep_seconds": 10},
            "search_settings": {"page_size": 50, "days_back": 1},
            "completeness": {"fail_on_incomplete_scan": False, "fail_on_lost_findings": True}
        }
    }


def _merge_custom_detectors(config_data: Dict[str, Any], config_folder: str) -> Dict[str, Any]:
    """Merge an optional customer-supplied detector file into `config_data`.

    Looks for `custom_trufflehog_detectors.yaml` in the same configs/ folder.
    Its `detectors:` are merged into the shipped list (custom wins on a name
    clash) and any `settings.excluded_detectors` are appended. The file is
    optional; if it's missing or invalid we keep the shipped config and carry
    on (logging the reason) rather than failing the scan. Lets customers add
    their own detectors without editing the file that ships with SAT.
    """
    custom_path = f"{config_folder}/custom_trufflehog_detectors.yaml"
    if not os.path.exists(custom_path):
        return config_data

    try:
        with open(custom_path, 'r') as file:
            custom = yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Custom detector file {custom_path} failed to parse — ignoring it: {str(e)}")
        return config_data

    if not isinstance(custom, dict):
        logger.warning(f"Custom detector file {custom_path} is not a YAML mapping — ignoring it")
        return config_data

    custom_detectors = custom.get("detectors") or []
    if custom_detectors:
        by_name = {d.get("name"): d for d in config_data.get("detectors", []) if isinstance(d, dict)}
        for d in custom_detectors:
            if isinstance(d, dict) and d.get("name"):
                by_name[d["name"]] = d  # custom overrides built-in of the same name
        config_data["detectors"] = list(by_name.values())
        logger.info(f"Merged {len(custom_detectors)} custom detector(s) from {custom_path}")

    custom_excluded = (custom.get("settings") or {}).get("excluded_detectors") or []
    if custom_excluded:
        existing = config_data.setdefault("settings", {}).setdefault("excluded_detectors", [])
        for x in custom_excluded:
            if x not in existing:
                existing.append(x)

    return config_data


def load_config_from_file():
    """Load detector/scan configuration from the YAML files in the configs directory.

    Loads the shipped `trufflehog_detectors.yaml`, then merges an optional
    customer-supplied `custom_trufflehog_detectors.yaml` if present. Falls back
    to a minimal built-in config if the shipped file cannot be loaded.
    """
    config_folder = getConfigPath()
    config_path = f"{config_folder}/trufflehog_detectors.yaml"

    logger.info(f"Loading configuration from: {config_path}")
    try:
        with open(config_path, 'r') as file:
            config_data = yaml.safe_load(file)
        if not isinstance(config_data, dict) or "detectors" not in config_data:
            raise ValueError(
                "config must be a YAML mapping with a top-level 'detectors:' key"
            )
    except Exception as e:
        logger.error(
            f"Could not load {config_path}: {str(e)}. "
            f"Using built-in detectors only; fix the file to load the full detector set."
        )
        return _default_config()

    return _merge_custom_detectors(config_data, config_folder)

def create_trufflehog_config(config_data: Dict[str, Any]) -> str:
    """Create TruffleHog configuration file from loaded config data."""
    config_file_path = "/tmp/trufflehog_config.yaml"
    
    # Extract just the detectors section for TruffleHog
    trufflehog_config = {"detectors": config_data.get("detectors", [])}
    
    try:
        with open(config_file_path, 'w') as file:
            yaml.dump(trufflehog_config, file, default_flow_style=False)
        
        logger.info(f"TruffleHog configuration created at: {config_file_path}")
        return config_file_path
    except Exception as e:
        logger.error(f"Failed to create TruffleHog config file: {str(e)}")
        raise

# Load configuration from external file
config_data = load_config_from_file()

# Configuration class using loaded values
class Config:
    """Configuration class for TruffleHog scanning parameters"""
    
    # File paths
    TRUFFLEHOG_BINARY = "/tmp/trufflehog"
    TRUFFLEHOG_CONFIG = create_trufflehog_config(config_data)
    TEMP_NOTEBOOKS_DIR = config_data.get("settings", {}).get("file_paths", {}).get("temp_notebooks", "/tmp/notebooks")
    RESULTS_LOG_FILE = config_data.get("settings", {}).get("file_paths", {}).get("results_log", "/tmp/trufflehog_scan_results.json")
    
    # API settings from config
    API_SLEEP_SECONDS = config_data.get("settings", {}).get("rate_limiting", {}).get("api_sleep_seconds", 10)
    PAGE_SIZE = config_data.get("settings", {}).get("search_settings", {}).get("page_size", 50)
    DAYS_BACK = config_data.get("settings", {}).get("search_settings", {}).get("days_back", 1)
    # Execucao parcial vira registro, nao falha. Perda de evidencia continua
    # reprovando: ali o segredo foi lido e o INSERT se perdeu, o que nenhuma
    # tratativa cobre. Ligar fail_on_incomplete_scan devolve o comportamento
    # antigo sem mexer no codigo.
    FAIL_ON_INCOMPLETE = bool(config_data.get("settings", {}).get("completeness", {}).get("fail_on_incomplete_scan", False))
    FAIL_ON_LOST_FINDINGS = bool(config_data.get("settings", {}).get("completeness", {}).get("fail_on_lost_findings", True))
    
    # TruffleHog settings from config
    EXCLUDED_DETECTORS = config_data.get("settings", {}).get("excluded_detectors", ["DatabricksToken"])

    # Concurrency: number of threads for I/O-bound work (workspace/list,
    # get-status, notebook export/FUSE copy). I/O-bound, so a pool well above
    # the core count is fine.
    MAX_WORKERS = config_data.get("settings", {}).get("performance", {}).get("max_workers", 16)
    # Directory where a batch of notebooks is materialized so TruffleHog can
    # scan them all in a single invocation instead of once per file.
    SCAN_BATCH_DIR = config_data.get("settings", {}).get("file_paths", {}).get("scan_batch_dir", "/tmp/notebook_scan_batch")

# Extract Databricks authentication context
# These are automatically available in Databricks notebooks
try:
    token = db_client.get_temporary_oauth_token() 
    base_url = json_["url"] 
    
    if not token or not base_url:
        raise ValueError("Unable to extract Databricks authentication context")
        
    logger.info(f"Successfully extracted Databricks context. Base URL: {base_url}")
    
except Exception as e:
    logger.error(f"Failed to extract Databricks context: {str(e)}")
    raise

# Create temporary directories if they don't exist
os.makedirs(Config.TEMP_NOTEBOOKS_DIR, exist_ok=True)
logger.info(f"Temporary directory created: {Config.TEMP_NOTEBOOKS_DIR}")

# Verify TruffleHog binary exists
if not os.path.exists(Config.TRUFFLEHOG_BINARY):
    error_msg = f"""
    ==========================================
    ERROR: TruffleHog binary not found!
    ==========================================

    Expected location: {Config.TRUFFLEHOG_BINARY}

    The TruffleHog security scanner was not successfully installed.
    This could be due to network restrictions or firewall policies.

    ACTION REQUIRED:
    Please contact your IT/Security team to allowlist access to:
      - raw.githubusercontent.com
      - github.com/trufflesecurity

    Or configure a proxy/mirror for downloading TruffleHog.
    ==========================================
    """
    logger.error(error_msg)
    raise FileNotFoundError(error_msg)

logger.info(f"✓ TruffleHog binary verified at: {Config.TRUFFLEHOG_BINARY}")

print("✅ Configuration loaded from external file and authentication setup completed successfully!")
print(f"📁 Config file: {Config.TRUFFLEHOG_CONFIG}")
print(f"🔧 Loaded {len(config_data.get('detectors', []))} custom detectors")
print(f"⚙️  API sleep: {Config.API_SLEEP_SECONDS}s, Page size: {Config.PAGE_SIZE}, Days back: {Config.DAYS_BACK}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Utility Functions
# MAGIC
# MAGIC This cell defines all the utility functions for API interactions, file operations, and secret scanning.

# COMMAND ----------

# Utility Functions for TruffleHog Secret Scanning

def get_yesterday_utc_midnight() -> int:
    """
    Get yesterday's date in UTC at midnight as milliseconds timestamp.
    
    Returns:
        int: Timestamp in milliseconds for yesterday at 00:00 UTC
    """
    today_utc_midnight = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_utc_midnight = today_utc_midnight - timedelta(days=Config.DAYS_BACK)
    return int(yesterday_utc_midnight.timestamp() * 1000)

def convert_time_to_databricks_format(env_time: int) -> int:
    """
    Convert environment time to Databricks format.
    
    Args:
        env_time (int): Time in milliseconds
        
    Returns:
        int: Time in Databricks format (milliseconds)
    """
    return int(env_time)

def generate_sha256_hash(secret: str) -> str:
    """
    Generate SHA-256 hash of a secret for secure logging.
    
    Args:
        secret (str): The secret string to hash
        
    Returns:
        str: SHA-256 hash in hexadecimal format
    """
    secret_bytes = secret.encode("utf-8")
    sha = hashlib.sha256()
    sha.update(secret_bytes)
    return sha.hexdigest()

def make_api_request(url: str, headers: Dict[str, str], data: Optional[Dict[str, Any]] = None) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
    """
    Make API request to Databricks with proper error handling.

    Returns a (json_or_none, status_or_none) tuple so callers can branch
    on HTTP status. Status is None when the request never reached the
    server (timeout / connection error).

    Rate limits (429) are retried internally with exponential backoff so a
    transient throttle no longer aborts pagination. We only sleep when the
    API actually throttles us — there is no unconditional inter-call sleep.
    """
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            response = requests.get(url, headers=headers, json=data, timeout=30)

            if response.status_code == 200:
                return response.json(), 200
            elif response.status_code == 429:
                if attempt == max_attempts - 1:
                    logger.warning(f"Rate limit persisted after {max_attempts} attempts for URL: {url}")
                    return None, 429
                backoff = Config.API_SLEEP_SECONDS * (2 ** attempt)
                logger.warning(f"Rate limit hit for URL: {url}. Backing off {backoff}s (attempt {attempt + 1}/{max_attempts})")
                time.sleep(backoff)
                continue
            else:
                logger.warning(f"API request failed. URL: {url}, Status: {response.status_code}")
                return None, response.status_code

        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for URL: {url}")
            return None, None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for URL: {url}. Error: {str(e)}")
            return None, None

    return None, 429

def _get_with_retry(url: str, what: str) -> Optional[requests.Response]:
    """
    Make a GET request, retrying with exponential backoff on HTTP 429.

    Notebook export and get-status are issued concurrently across MAX_WORKERS
    threads, which can trip workspace rate limits. Retrying keeps a throttled
    notebook in the scan instead of dropping it.

    Args:
        url (str): URL to request
        what (str): Short description of the operation, used in log messages

    Returns:
        Optional[requests.Response]: Response, or None if the request never
            reached the server
    """
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "databricks-sat/0.1.0"}
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            response = requests.get(url, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error during {what}: {str(e)}")
            return None

        if response.status_code != 429:
            return response

        if attempt == max_attempts - 1:
            logger.warning(f"Rate limit persisted after {max_attempts} attempts during {what}")
            return response

        backoff = Config.API_SLEEP_SECONDS * (2 ** attempt)
        logger.warning(
            f"Rate limit hit during {what}. Backing off {backoff}s "
            f"(attempt {attempt + 1}/{max_attempts})"
        )
        time.sleep(backoff)

    return None


def check_notebook_status(notebook_path: str) -> int:
    """
    Check if a notebook exists and is accessible.

    Retries on HTTP 429 so a throttled response doesn't drop the notebook.

    Args:
        notebook_path (str): Path to the notebook

    Returns:
        int: HTTP status code (200=accessible, 403=no permission, 404=not found)
    """
    check_url = f"{base_url}/api/2.0/workspace/get-status?path={quote(notebook_path)}"
    response = _get_with_retry(check_url, f"get-status for {notebook_path}")
    if response is None:
        return 500  # treated as an unexpected status by callers

    # A mensagem que a API devolve junto de um status de erro e a unica fonte que
    # explica o motivo. Guardada aqui para o registro por objeto poder cita-la em
    # vez de repetir uma frase nossa — foi essa falta que tornou um 403 opaco.
    if response.status_code != 200:
        try:
            corpo = response.json()
            motivo = f"{corpo.get('error_code', '')} {corpo.get('message', '')}".strip()
        except Exception:
            motivo = (response.text or "")[:300]
        _last_api_error[notebook_path] = motivo or f"HTTP {response.status_code} sem corpo"

    return response.status_code


def _get_object_metadata(path: str) -> Optional[Dict[str, Any]]:
    """Return the full /workspace/get-status response body for `path`.

    Used by the workspace/list-based discovery fallback to read
    `modified_at` for time-window filtering.
    """
    url = f"{base_url}/api/2.0/workspace/get-status?path={quote(path)}"
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "databricks-sat/0.1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200:
            return r.json()
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"workspace/get-status failed for {path}: {str(e)}")
        return None


def _list_dir(path: str) -> List[Dict[str, Any]]:
    """Single /workspace/list call. Returns the raw objects list (empty on error/404).

    404 is normal for tree roots that don't exist on every workspace
    (e.g. /Repos on workspaces without Git integration).

    Uses _get_with_retry so an HTTP 429 is retried with exponential backoff
    instead of silently dropping the whole subtree from the scan. Recursive
    discovery bursts many list calls in quick succession, which is exactly
    when workspace rate limits trigger.
    """
    url = f"{base_url}/api/2.0/workspace/list?path={quote(path)}"
    r = _get_with_retry(url, f"workspace/list {path}")
    if r is None:
        logger.warning(f"workspace/list failed for {path} (no response)")
        return []
    if r.status_code != 200:
        if r.status_code != 404:
            logger.warning(f"workspace/list returned {r.status_code} for {path}")
        return []
    return r.json().get("objects", [])


def discover_notebooks_via_workspace_list(time_filter_enabled: bool,
                                          last_edited_after: Optional[int]) -> List[Dict[str, Any]]:
    """Fallback notebook discovery using /workspace/list (+ /get-status only when needed).

    Used when /search-midtier/unified-search rejects token-based auth
    (returns 403). See GitHub issue #330 for context.

    As raizes vem de um /workspace/list na raiz, nao de uma lista fixa. A lista
    fixa (/Users, /Shared, /Repos) deixava de fora qualquer arvore que o
    workspace tivesse alem dessas tres, e o objeto simplesmente nao aparecia:
    nem como lido, nem como excecao. Perguntar a raiz cobre o que existe hoje e
    o que for criado depois, sem exigir alteracao de codigo.

    Performance: directory traversal is fanned out across a thread pool one
    level at a time instead of recursing serially, and the per-leaf
    /workspace/get-status call is skipped entirely when the list response
    already carries `modified_at`. get-status is only issued (and then in
    parallel) for the leaves that lack it — eliminating the O(notebooks)
    serial round-trips that made this path time out on large workspaces.
    """
    cutoff_ms = last_edited_after if time_filter_enabled else None

    # Phase 1: parallel breadth-first directory traversal.
    leaves: List[Dict[str, Any]] = []

    # Raizes descobertas, nao presumidas. Se a raiz nao responder, cai para as
    # tres arvores historicas para nao ficar sem nenhuma origem.
    raizes = [o["path"] for o in _list_dir("/")
              if o.get("path") and o.get("object_type") in ("DIRECTORY", "REPO")]
    if not raizes:
        logger.warning("workspace/list na raiz nao devolveu diretorios; usando as raizes padrao")
        raizes = ["/Users", "/Shared", "/Repos"]
    logger.info(f"Raizes descobertas para a varredura: {raizes}")
    print(f"🌳 Raizes descobertas: {', '.join(raizes)}")

    pending: List[str] = raizes
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        while pending:
            next_dirs: List[str] = []
            for objs in pool.map(_list_dir, pending):
                for obj in objs:
                    obj_type = obj.get("object_type")
                    if not obj.get("path"):
                        continue
                    if obj_type in ("DIRECTORY", "REPO"):
                        next_dirs.append(obj["path"])
                    elif obj_type in ("NOTEBOOK", "FILE"):
                        leaves.append(obj)
            pending = next_dirs

    # Phase 2: time-window filter (only when enabled).
    if cutoff_ms is None:
        kept = leaves
    else:
        kept = [o for o in leaves if "modified_at" in o and o.get("modified_at", 0) >= cutoff_ms]
        need_meta = [o for o in leaves if "modified_at" not in o]
        if need_meta:
            def _keep_if_recent(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                meta = _get_object_metadata(obj.get("path", ""))
                if meta and meta.get("modified_at", 0) >= cutoff_ms:
                    return obj
                return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
                kept.extend(o for o in pool.map(_keep_if_recent, need_meta) if o is not None)

    # Normalize to the {id, name, workspace_path} shape the batch processor expects.
    normalized = [{
        "id": str(obj.get("object_id", "")),
        "name": obj.get("path", "").rsplit("/", 1)[-1],
        "workspace_path": obj.get("path", "").rsplit("/", 1)[0],
    } for obj in kept]

    # Descarta o que nao e codigo-fonte antes de qualquer chamada de export.
    return filter_non_source(normalized)

def get_fuse_path(workspace_path: str) -> Optional[str]:
    """Find the actual file on the FUSE mount by trying common extensions."""
    base_path = f"/Workspace{workspace_path}"
    for ext in [".ipynb", ".sql", ".py", ".r", ".scala", ""]:
        candidate = f"{base_path}{ext}"
        if os.path.exists(candidate):
            return candidate
    return None

def export_notebook_content(notebook_path: str) -> Optional[Dict[str, Any]]:
    """
    Export notebook content from Databricks workspace.

    Retries on HTTP 429 so a throttled export doesn't silently drop the
    notebook from the scan.

    Args:
        notebook_path (str): Path to the notebook

    Returns:
        Optional[Dict[str, Any]]: Notebook export response or None if error
    """
    url = f"{base_url}/api/2.0/workspace/export?path={quote(notebook_path)}"
    response = _get_with_retry(url, f"export of {notebook_path}")
    if response is None:
        return None
    try:
        response.raise_for_status()
        return response.json()
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.error(f"Error exporting notebook content for {notebook_path}: {str(e)}")
        return None

def decode_and_write_content(content: str, output_path: str) -> bool:
    """
    Decode base64 content and write to file.
    
    Args:
        content (str): Base64 encoded content
        output_path (str): Path to write decoded content
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        decoded_content = base64.b64decode(content).decode("utf-8")
    except UnicodeDecodeError:
        # Workspace discovery returns every object in a folder, including
        # images and other binaries committed alongside notebooks. They hold
        # no scannable text, so they are skipped rather than treated as a
        # failed read.
        skip_stats["non_text"] += 1
        logger.info(f"Skipping non-text object (binary content): {output_path}")
        return False
    except Exception as e:
        logger.error(f"Error decoding content for {output_path}: {str(e)}")
        return False

    try:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(decoded_content)
        return True
    except Exception as e:
        logger.error(f"Error writing content to {output_path}: {str(e)}")
        return False

def scan_for_secrets(file_path: str) -> Optional[str]:
    """
    Run TruffleHog scan on a file to detect secrets.
    Runs two scans: one with built-in detectors and one with custom detectors,
    then combines the results.
    
    Args:
        file_path (str): Path to file to scan
        
    Returns:
        Optional[str]: TruffleHog output in JSON format or None if error
    """
    all_results = []
    
    # Scan 1: Run with built-in detectors (excluding specified ones)
    excluded_detectors = ",".join(Config.EXCLUDED_DETECTORS)
    builtin_command_args = [
        Config.TRUFFLEHOG_BINARY,
        "filesystem",
        file_path,
        f"--exclude-detectors={excluded_detectors}",
        "--no-update",
        "-j"
    ]
    
    try:
        logger.info(f"Running built-in detectors scan on {file_path}")
        logger.info(f"Built-in scan command: {' '.join(builtin_command_args)}")
        result = subprocess.run(
            builtin_command_args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        logger.info(f"Built-in scan exit code: {result.returncode}")
        
        if result.stdout:
            all_results.append(result.stdout)
            logger.info(f"Built-in detectors scan completed with {len(result.stdout.splitlines())} output lines")
            logger.debug(f"Built-in scan produced {len(result.stdout)} bytes across {len(result.stdout.splitlines())} hits")
        else:
            logger.info(f"Built-in detectors scan completed with no secrets found")
            print(f"Built-in scan stdout was empty")
        
        if result.stderr:
            logger.info(f"Built-in scan stderr: {result.stderr}")
            logger.debug(f"Built-in scan stderr: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error(f"Built-in detectors scan timed out for file: {file_path}")
    
    # Scan 2: Run with custom detectors from config file
    custom_command_args = [
        Config.TRUFFLEHOG_BINARY,
        "filesystem",
        file_path,
        "--no-update",
        "--config",
        Config.TRUFFLEHOG_CONFIG,
        "-j"
    ]
    
    try:
        logger.info(f"Running custom detectors scan on {file_path}")
        result = subprocess.run(
            custom_command_args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        if result.stdout:
            all_results.append(result.stdout)
            logger.info(f"Custom detectors scan completed with output")
        else:
            logger.info(f"Custom detectors scan completed with no secrets found")
        
        if result.stderr:
            logger.debug(f"Custom scan stderr: {result.stderr}")
        if result.returncode != 0:
            logger.warning(f"Custom scan returned non-zero exit code: {result.returncode}")
    except subprocess.TimeoutExpired:
        logger.error(f"Custom detectors scan timed out for file: {file_path}")
    
    # Combine results from both scans
    if all_results:
        return "\n".join(all_results)
    else:
        logger.warning(f"Both scans completed but no results found for {file_path}")
        return ""

def process_trufflehog_output(trufflehog_output: str) -> List[Dict[str, str]]:
    """
    Process TruffleHog JSON output and extract relevant information.
    
    Args:
        trufflehog_output (str): Raw TruffleHog output in JSON format
        
    Returns:
        List[Dict[str, str]]: List of detected secrets with hashed values
    """
    results = []
    
    if not trufflehog_output or not trufflehog_output.strip():
        return results
    
    for line in trufflehog_output.strip().splitlines():
        try:
            data = json.loads(line)
            detector_name = (
                (data.get("ExtraData") or {}).get("name")
                or data.get("DetectorName", "unknown")
            )
            raw_value = data.get("Raw", "")
            
            if raw_value:
                # Generate SHA-256 hash for security (don't log actual secrets)
                raw_sha = generate_sha256_hash(raw_value)
                
                # Add metadata about the detection
                result = {
                    "DetectorName": detector_name,
                    "Raw_SHA": raw_sha,
                    "SourceFile": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "Unknown"),
                    "Verified": data.get("Verified", False)
                }
                results.append(result)
                
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse TruffleHog output line: {line}. Error: {str(e)}")
            continue
    
    return results

print("✅ Utility functions defined successfully!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3.5: Database Storage Functions
# MAGIC
# MAGIC This cell contains functions for storing secret scan results in the SAT database.

# COMMAND ----------

# Table setup runs once per scan rather than once per finding: it issues a
# CREATE TABLE IF NOT EXISTS plus one ALTER TABLE per column for comments.
_results_table_ready = False

# Findings attempted vs. actually persisted, used to detect a partial write.
insert_stats = {"attempted": 0, "written": 0, "failed": 0}


def ensure_results_table() -> None:
    """Create and annotate the results table once per scan."""
    global _results_table_ready
    if _results_table_ready:
        return
    create_notebooks_secret_scan_results_table()
    _results_table_ready = True


def _sql_str(value: Any) -> str:
    """Render a value as a single-quoted SQL literal, escaping embedded quotes."""
    return "'" + str(value or "").replace("'", "''") + "'"


def insert_secret_scan_results(workspace_id: str, notebook_metadata: Dict[str, Any], run_id: int) -> None:
    """
    Insert secret scan results for a single notebook.

    Args:
        workspace_id (str): Workspace ID being scanned
        notebook_metadata (Dict[str, Any]): Notebook metadata with secret details
        run_id (int): SAT run ID for tracking
    """
    insert_secret_scan_results_batch(workspace_id, [notebook_metadata], run_id)


def insert_secret_scan_results_batch(workspace_id: str,
                                     notebook_metadatas: List[Dict[str, Any]],
                                     run_id: int) -> None:
    """
    Insert all findings for a batch of notebooks in a single statement.

    Only notebooks with secrets are persisted, to avoid table bloat. Insert
    failures are logged and counted in `insert_stats` rather than raised, so a
    failed batch does not abort the scan; the caller checks those counters to
    report an incomplete run.

    Args:
        workspace_id (str): Workspace ID being scanned
        notebook_metadatas (List[Dict[str, Any]]): Notebook metadata with secret details
        run_id (int): SAT run ID for tracking
    """
    import time

    rows: List[str] = []
    scan_time = time.time()

    for notebook_metadata in notebook_metadatas:
        if notebook_metadata.get("secrets_found", 0) <= 0:
            continue

        notebook_id = notebook_metadata.get("object_id", "")
        notebook_path = notebook_metadata.get("path", "")
        notebook_name = notebook_metadata.get("name", "")
        secrets_found = notebook_metadata.get("secrets_found", 0)

        for secret in notebook_metadata.get("secret_details", []):
            rows.append(
                "({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, cast({} as timestamp))".format(
                    _sql_str(workspace_id),
                    _sql_str(notebook_id),
                    _sql_str(notebook_path),
                    _sql_str(notebook_name),
                    _sql_str(secret.get("DetectorName", "Unknown")),
                    _sql_str(secret.get("Raw_SHA", "")),
                    _sql_str(secret.get("SourceFile", "")),
                    "true" if secret.get("Verified", False) else "false",
                    int(secrets_found),
                    int(run_id),
                    scan_time,
                )
            )

    if not rows:
        return

    insert_stats["attempted"] += len(rows)

    # A tabela recebe gravacoes dos workspaces que rodam em paralelo. Um conflito
    # de metadados ou de escrita concorrente e transitorio: perder o achado por
    # isso seria pior do que tentar de novo. Ate 4 tentativas, com espera
    # crescente e jitter para os concorrentes nao voltarem juntos.
    ultima_falha = None
    for tentativa in range(4):
        try:
            ensure_results_table()
            spark.sql(
                f"""
                INSERT INTO {json_["analysis_schema_name"]}.notebooks_secret_scan_results
                (workspace_id, notebook_id, notebook_path, notebook_name, detector_name,
                 secret_sha256, source_file, verified, secrets_found, run_id, scan_time)
                VALUES {", ".join(rows)}
                """
            )
            insert_stats["written"] += len(rows)
            logger.info(f"Persisted {len(rows)} secret finding(s)")
            return
        except Exception as e:
            ultima_falha = e
            transitorio = any(marca in str(e) for marca in (
                "DELTA_METADATA_CHANGED", "MetadataChangedException",
                "ConcurrentAppendException", "DELTA_CONCURRENT_APPEND",
                "ConcurrentWriteException",
            ))
            if not transitorio or tentativa == 3:
                break
            espera = (2 ** tentativa) + random.uniform(0, 1)
            logger.warning(
                f"Conflito concorrente ao gravar {len(rows)} achado(s); "
                f"nova tentativa em {espera:.1f}s ({tentativa + 1}/3)"
            )
            time.sleep(espera)

    insert_stats["failed"] += len(rows)
    logger.error(f"Failed to insert {len(rows)} secret scan result(s): {str(ultima_falha)}")

def record_object_events(workspace_id: str, run_id: Optional[int], source: str) -> None:
    """Grava em lote os objetos nao escaneados em {analysis_schema}.scan_object_events.

    Sem isso o detalhe vive so no log do job, que expira — e a comparacao entre
    execucoes fica impossivel.
    """
    if not object_events:
        return
    try:
        create_scan_object_events_table()
        schema = json_["analysis_schema_name"]
        ws = _sql_str(workspace_id)
        rid = str(int(run_id)) if run_id is not None else "NULL"
        src = _sql_str(source)

        # Lotes para nao montar um INSERT gigante num workspace com muitos eventos.
        tamanho = 500
        for inicio in range(0, len(object_events), tamanho):
            fatia = object_events[inicio:inicio + tamanho]
            valores = ",".join(
                f"({ws}, {rid}, {src}, {_sql_str(caminho)}, {_sql_str(oid)}, "
                f"{_sql_str(desfecho)}, {_sql_str(detalhe)}, current_timestamp())"
                for caminho, oid, desfecho, detalhe in fatia
            )
            spark.sql(
                f"""INSERT INTO {schema}.scan_object_events
                    (workspace_id, run_id, source, object_path, object_id, outcome, detail, check_time)
                    VALUES {valores}"""
            )
        logger.info(f"Object events recorded: {len(object_events)}")
    except Exception as exc:
        logger.error(f"Failed to record object events: {exc}")


def record_scan_started(workspace_id: str, run_id: Optional[int], source: str) -> None:
    """Abre a execucao em {analysis_schema}.scan_discovery_stats com status EM EXECUCAO.

    O registro final so acontece no fim da varredura. Se o notebook morrer antes
    — timeout, cluster derrubado, OOM — nenhuma linha era gravada e o workspace
    sumia do relatorio: ausencia de linha nao e um sinal que alguem consegue ver.
    Esta linha de abertura transforma essa ausencia em presenca. A linha final e
    um novo append; as views leem a mais recente por (workspace, run, source),
    entao o que ficar EM EXECUCAO depois do job terminar e execucao interrompida.

    Append, nao UPDATE: varias tarefas escrevem na mesma particao de data ao
    mesmo tempo, e UPDATE concorrente em Delta ja nos custou conflito antes.
    """
    try:
        create_scan_discovery_stats_table()
        schema = json_["analysis_schema_name"]
        rid = str(int(run_id)) if run_id is not None else "NULL"
        spark.sql(
            f"""INSERT INTO {schema}.scan_discovery_stats
                (workspace_id, run_id, source, discovered, filtered, eligible, scanned,
                 skipped_empty, skipped_binary, unscanned, findings_attempted,
                 findings_unwritten, status, filter_reason, filter_count, check_time)
                VALUES ({_sql_str(workspace_id)}, {rid}, {_sql_str(source)},
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 'EM EXECUCAO', NULL, NULL, current_timestamp())"""
        )
        logger.info(f"Scan opened for workspace {workspace_id}, run_id {run_id}")
    except Exception as exc:
        # Nao derruba a varredura: a linha de abertura e instrumentacao, nao o
        # trabalho. Perder o marcador e pior que nao ter scan? Nao.
        logger.error(f"Failed to record scan start: {exc}")


def record_discovery_stats(workspace_id: str, run_id: Optional[int], source: str,
                           discovered: int, filtered: int, eligible: int,
                           scanned: int, skipped: int, unscanned: int,
                           attempted: int = 0, unwritten: int = 0,
                           status: str = "COMPLETO") -> None:
    """Grava o funil de descoberta em {analysis_schema}.scan_discovery_stats.

    Uma linha de resumo por workspace (filter_reason NULL) e uma linha por
    motivo de descarte, para que o que foi filtrado fique auditavel depois da
    execucao — e nao apenas no log do job, que expira.
    """
    try:
        create_scan_discovery_stats_table()
        schema = json_["analysis_schema_name"]
        ws = _sql_str(workspace_id)
        rid = str(int(run_id)) if run_id is not None else "NULL"
        src = _sql_str(source)

        st = _sql_str(status)
        comum = (f"({ws}, {rid}, {src}, {discovered}, {filtered}, {eligible}, {scanned}, "
                 f"{skip_stats['empty']}, {skip_stats['non_text']}, {unscanned}, "
                 f"{attempted}, {unwritten}, {st}, ")

        linhas = [comum + "NULL, NULL, current_timestamp())"]
        for motivo, qtd in sorted(filtered_reasons.items(), key=lambda kv: -kv[1]):
            linhas.append(comum + f"{_sql_str(motivo)}, {qtd}, current_timestamp())")

        spark.sql(
            f"""INSERT INTO {schema}.scan_discovery_stats
                (workspace_id, run_id, source, discovered, filtered, eligible, scanned,
                 skipped_empty, skipped_binary, unscanned, findings_attempted,
                 findings_unwritten, status, filter_reason, filter_count, check_time)
                VALUES {",".join(linhas)}"""
        )
        logger.info(f"Discovery stats recorded: {discovered} discovered, {filtered} filtered, {eligible} eligible")
        # Views de relatorio: recriadas junto com os dados, para nao dependerem de
        # uma execucao do initializer. Aqui, e nao no registro de excecoes, porque
        # aquele retorna cedo quando a execucao foi limpa.
        create_scan_reporting_views()
    except Exception as exc:
        logger.error(f"Failed to record discovery stats: {exc}")


def insert_no_secrets_tracking_row(workspace_id: str, run_id: int) -> None:
    """
    Insert a single tracking row for a scan run where no secrets were found.
    Ensures only one row per run_id exists.
    """
    try:
        # Ensure table exists
        create_notebooks_secret_scan_results_table()
        logger.info(f"Inserting no-secrets tracking row for workspace_id: {workspace_id}, run_id: {run_id}")

        # Check if a row already exists for this run_id
        existing = spark.sql(f"""
            SELECT COUNT(*) as cnt
            FROM {json_["analysis_schema_name"]}.notebooks_secret_scan_results
            WHERE run_id = {run_id}
        """).collect()[0]["cnt"]

        if existing > 0:
            logger.info(f"No-secrets row already exists for run_id {run_id}, skipping insert")
            return

        # Escape single quotes in workspace_id for SQL
        workspace_id_escaped = workspace_id.replace("'", "''")

        # Insert placeholder row
        spark.sql(f"""
            INSERT INTO {json_["analysis_schema_name"]}.notebooks_secret_scan_results
            (workspace_id, notebook_id, notebook_path, notebook_name, detector_name,
             secret_sha256, source_file, verified, secrets_found, run_id, scan_time)
            VALUES ('{workspace_id_escaped}', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, {run_id}, current_timestamp())
        """)
        logger.info(f"No-secrets tracking row inserted successfully for run_id: {run_id}")

    except Exception as e:
        logger.error(f"Failed to insert no-secrets tracking row: {str(e)}")
        # Do not raise to avoid stopping workflow

def get_current_run_id() -> int:
    """
    Get a new SAT run ID for tracking scan results.
    Inserts a new row into run_number_table and retrieves the auto-generated runID.

    Returns:
        int: New run ID (auto-generated by IDENTITY column)
    """
    try:
        # Insert new run into run_number_table (runID is auto-generated as IDENTITY column)
        # Only insert check_time, let the database auto-generate runID
        spark.sql(f'''
            INSERT INTO {json_["analysis_schema_name"]}.run_number_table (check_time)
            VALUES (current_timestamp())
        ''')

        # Retrieve the auto-generated runID (it will be the max value)
        result = spark.sql(f'''
            SELECT max(runID) as new_run_id
            FROM {json_["analysis_schema_name"]}.run_number_table
        ''').collect()

        new_run_id = result[0]["new_run_id"]

        logger.info(f"Created new SAT run_id: {new_run_id}")
        return new_run_id

    except Exception as e:
        logger.error(f"Failed to get or create new run ID: {str(e)}")
        # Fallback: use current timestamp as unique run ID
        fallback_run_id = int(time.time())
        logger.info(f"Using fallback run_id: {fallback_run_id}")
        return fallback_run_id


print("✅ Database storage functions defined successfully!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Main Scanning Functions
# MAGIC
# MAGIC This cell contains the main functions for processing notebooks and orchestrating the secret scanning workflow.

# COMMAND ----------

# Main Scanning Functions

def scan_notebook_for_secrets(notebook_path: str, object_id: str) -> Optional[List[Dict[str, str]]]:
    """
    Scan a single notebook for secrets using TruffleHog.
    
    Args:
        notebook_path (str): Path to the notebook in Databricks workspace
        object_id (str): Unique identifier for the notebook
        
    Returns:
        Optional[List[Dict[str, str]]]: List of detected secrets or None if error
    """
    try:
        output_file_path = os.path.join(Config.TEMP_NOTEBOOKS_DIR, f"notebook_content_{object_id}.txt")

        # Try FUSE mount first (fast local copy), fall back to API export
        fuse_path = get_fuse_path(notebook_path)
        if fuse_path:
            logger.info(f"Using FUSE mount: {fuse_path}")
            try:
                os.makedirs(Config.TEMP_NOTEBOOKS_DIR, exist_ok=True)
                shutil.copy2(fuse_path, output_file_path)
            except Exception as e:
                logger.warning(f"FUSE copy failed for {fuse_path}, falling back to API: {e}")
                fuse_path = None  # trigger API fallback below

        if not fuse_path:
            # API fallback: check status, export, decode
            notebook_status = check_notebook_status(notebook_path)

            if notebook_status == 200:
                export_response = export_notebook_content(notebook_path)
                if export_response is None:
                    record_object_event(notebook_path, notebook_id, "export_failed", "export retornou vazio")
                    logger.warning(f"Failed to export notebook content: {notebook_path}")
                    return None

                content = export_response.get("content")
                if not content:
                    skip_stats["empty"] += 1
                    record_object_event(notebook_path, notebook_id, "empty", "")
                    logger.info(f"Skipping empty object (no content): {notebook_path}")
                    return None

                if not decode_and_write_content(content, output_file_path):
                    record_object_event(notebook_path, notebook_id, "non_text", "conteudo nao decodificou como texto")
                    logger.error(f"Failed to write notebook content to file: {output_file_path}")
                    return None

                logger.info(f"Notebook content exported via API to: {output_file_path}")

            elif notebook_status == 403:
                record_object_event(notebook_path, notebook_id, "access_denied")
                logger.warning(f"Access denied for notebook: {notebook_path}")
                return None
            elif notebook_status == 404:
                stale_stats["stale_path"] += 1
                record_object_event(notebook_path, notebook_id, "stale_path", "HTTP 404: caminho mudou entre descoberta e leitura")
                logger.warning(f"Path no longer valid (moved or removed since discovery): {notebook_path}")
                return None
            else:
                record_object_event(notebook_path, notebook_id, "unexpected_status", _last_api_error.pop(notebook_path, "") or f"HTTP {notebook_status}")
                logger.warning(f"Unexpected status {notebook_status} for notebook: {notebook_path}")
                return None

        # Scan for secrets using TruffleHog
        trufflehog_output = scan_for_secrets(output_file_path)
        if trufflehog_output is None:
            logger.warning(f"TruffleHog scan failed for: {notebook_path}")
            return None

        # Process TruffleHog output
        results = process_trufflehog_output(trufflehog_output)

        if results:
            logger.info(f"Found {len(results)} potential secrets in notebook: {notebook_path}")
            for result in results:
                logger.info(f"Secret detected - Type: {result['DetectorName']}, SHA: {result['Raw_SHA'][:16]}...")
        else:
            logger.info(f"No secrets found in notebook: {notebook_path}")

        return results
            
    except Exception as e:
        logger.error(f"Error scanning notebook {notebook_path}: {str(e)}")
        return None

def _materialize_notebook(notebook: Dict[str, Any], scan_dir: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Write one notebook's content into `scan_dir` so a whole batch can be
    scanned by TruffleHog in a single invocation.

    The on-disk filename is the notebook's object_id, which lets findings be
    mapped back to the notebook by source-file basename after the scan.
    Mirrors the original FUSE-first / API-export fallback. Returns
    (scan_file_path, metadata) on success, or None if the notebook could not
    be materialized (missing fields, no access, export failure).
    """
    notebook_id = notebook.get("id", "")
    notebook_name = notebook.get("name", "")
    parent_path = notebook.get("workspace_path", "")

    if not notebook_id or not notebook_name:
        logger.warning("Skipping notebook with missing ID or name")
        return None
    if os.sep in str(notebook_id):
        logger.warning(f"Skipping notebook with unsafe id: {notebook_id}")
        return None

    temp_path = f"{parent_path}/{notebook_name}"
    # O caminho segue cru daqui para frente. get_fuse_path monta um caminho de
    # filesystem, e check_notebook_status/export_notebook_content ja aplicam
    # quote() ao montar a URL. Encodar aqui gerava %2520 na chamada da API: um
    # 404 falso registrado como stale_path, e o notebook sumia do relatorio sem
    # aparecer como problema. Atingia todo caminho com espaco ou acento.
    path = temp_path
    metadata = {"object_id": notebook_id, "path": path, "name": notebook_name}
    scan_file = os.path.join(scan_dir, str(notebook_id))

    try:
        # Try FUSE mount first (fast local copy), fall back to API export.
        fuse_path = get_fuse_path(path)
        if fuse_path:
            try:
                shutil.copy2(fuse_path, scan_file)
                return scan_file, metadata
            except Exception as e:
                logger.warning(f"FUSE copy failed for {fuse_path}, falling back to API: {e}")

        notebook_status = check_notebook_status(path)
        if notebook_status == 200:
            export_response = export_notebook_content(path)
            if not export_response:
                record_object_event(temp_path, notebook_id, "export_failed", "export retornou vazio")
                logger.warning(f"Failed to export notebook content: {temp_path}")
                return None
            content = export_response.get("content")
            if not content:
                skip_stats["empty"] += 1
                record_object_event(temp_path, notebook_id, "empty", "")
                logger.info(f"Skipping empty object (no content): {temp_path}")
                return None
            if not decode_and_write_content(content, scan_file):
                record_object_event(temp_path, notebook_id, "non_text", "conteudo nao decodificou como texto")
                logger.error(f"Failed to write notebook content to file: {scan_file}")
                return None
            return scan_file, metadata
        elif notebook_status == 403:
            record_object_event(temp_path, notebook_id, "access_denied")
            logger.warning(f"Access denied for notebook: {temp_path}")
        elif notebook_status == 404:
            # O objeto existia na descoberta e nao esta mais neste caminho:
            # movido ou removido entre a listagem e a leitura. Confirmado em
            # 24/08/2026 via system.access.audit, com moveNotebook 4s antes do
            # export. Nao reprova a execucao; a proxima janela pega o caminho novo.
            stale_stats["stale_path"] += 1
            record_object_event(temp_path, notebook_id, "stale_path", "HTTP 404: caminho mudou entre descoberta e leitura")
            logger.warning(f"Path no longer valid (moved or removed since discovery): {temp_path}")
        else:
            record_object_event(temp_path, notebook_id, "unexpected_status", _last_api_error.pop(temp_path, "") or f"HTTP {notebook_status}")
            logger.warning(f"Unexpected status {notebook_status} for notebook: {temp_path}")
        return None
    except Exception as e:
        record_object_event(temp_path, notebook.get("id", ""), "error", str(e)[:400])
        logger.error(f"Error materializing notebook {temp_path}: {str(e)}")
        return None


def _scan_and_record_chunk(chunk: List[Dict[str, Any]],
                           results_list: List[Dict[str, Any]],
                           output_filename: Optional[str],
                           run_id: Optional[int],
                           workspace_id: Optional[str]) -> None:
    """Materialize a chunk of notebooks in parallel, scan the whole chunk with
    a single TruffleHog pass, then attribute findings back to each notebook.

    Uses a fresh, unique temp directory per chunk (tempfile.mkdtemp). This is
    required for correctness: when multiple workspaces are scanned concurrently,
    every child notebook shares the same driver-local filesystem, so a fixed
    shared directory would let one scan's files clobber another's.
    """
    os.makedirs(Config.SCAN_BATCH_DIR, exist_ok=True)
    scan_dir = tempfile.mkdtemp(dir=Config.SCAN_BATCH_DIR)
    try:
        # Phase 1: materialize notebook contents in parallel (I/O-bound).
        basename_to_meta: Dict[str, Dict[str, Any]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            for res in pool.map(lambda nb: _materialize_notebook(nb, scan_dir), chunk):
                if res is None:
                    continue
                scan_file, metadata = res
                basename_to_meta[os.path.basename(scan_file)] = metadata

        # Record metadata + log line for every materialized notebook.
        for metadata in basename_to_meta.values():
            results_list.append(metadata)
            if output_filename:
                try:
                    with open(output_filename, mode="a", encoding="utf-8") as output_file:
                        json.dump(metadata, output_file)
                        output_file.write("\n")
                except IOError as e:
                    logger.error(f"Failed to write to output file {output_filename}: {str(e)}")

        if not basename_to_meta:
            return

        # Phase 2: a single TruffleHog pass over the whole chunk directory
        # (built-in + custom detectors), instead of two subprocesses per file.
        trufflehog_output = scan_for_secrets(scan_dir)
        findings = process_trufflehog_output(trufflehog_output) if trufflehog_output else []

        # Phase 3: attribute findings back to notebooks by source-file basename.
        findings_by_notebook: Dict[str, List[Dict[str, str]]] = {}
        for finding in findings:
            key = os.path.basename(finding.get("SourceFile", ""))
            findings_by_notebook.setdefault(key, []).append(finding)

        # Phase 4: set counts and surface alerts.
        for key, metadata in basename_to_meta.items():
            secret_results = findings_by_notebook.get(key, [])
            if secret_results:
                metadata["secrets_found"] = len(secret_results)
                metadata["secret_details"] = secret_results
                print(f"🚨 SECRETS DETECTED in {metadata['path']}:")
                print(json.dumps(secret_results, indent=2))
            else:
                metadata["secrets_found"] = 0

        # Phase 5: persist the whole chunk in one statement.
        if run_id is not None and workspace_id is not None:
            insert_secret_scan_results_batch(
                workspace_id, list(basename_to_meta.values()), run_id
            )
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


def _process_notebook_batch(batch: List[Dict[str, Any]],
                            results_list: List[Dict[str, Any]],
                            output_filename: Optional[str] = None,
                            run_id: Optional[int] = None,
                            workspace_id: Optional[str] = None) -> None:
    """Scan each notebook in `batch` for secrets and record results.

    `batch` is a list of {id, name, workspace_path} dicts — the shape
    unified-search returns natively. The workspace/list fallback
    synthesizes the same shape so both discovery paths share this
    downstream processor (TruffleHog scan, DB insert, log file write).

    Notebooks are processed in bounded chunks: each chunk is materialized in
    parallel and scanned with a single TruffleHog invocation. This replaces
    the previous per-notebook loop that spawned two subprocesses per file and
    exported notebooks one at a time — the dominant cost on large workspaces.
    """
    logger.info(f"Processing {len(batch)} notebooks from discovery batch")

    chunk_size = max(1, Config.MAX_WORKERS * 8)
    for start in range(0, len(batch), chunk_size):
        _scan_and_record_chunk(batch[start:start + chunk_size],
                               results_list, output_filename, run_id, workspace_id)


def process_search_response(response: Dict[str, Any], results_list: List[Dict[str, Any]],
                          output_filename: Optional[str] = None, run_id: Optional[int] = None,
                          workspace_id: Optional[str] = None) -> Optional[str]:
    """
    Process unified-search API response and scan returned notebooks for secrets.

    Returns the next-page token (or None if there are no more pages).
    """
    if not response:
        logger.warning("Empty response received")
        return None

    eligible = filter_non_source(response.get("results", []))
    _process_notebook_batch(eligible, results_list,
                            output_filename, run_id, workspace_id)
    return response.get("next_page_token")

print("✅ Main scanning functions defined successfully!")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Execute Secret Scanning
# MAGIC
# MAGIC This cell executes the main scanning workflow to search for notebooks and scan them for secrets.

# COMMAND ----------

# Execute TruffleHog Secret Scanning Workflow

def main_scanning_workflow():
    """
    Main function to orchestrate the secret scanning process.
    """
    print("🔍 Starting TruffleHog Secret Scanning Workflow")
    print("=" * 60)

    # Get current workspace ID and run ID for database storage
    workspace_id = json_.get("workspace_id", "unknown")

    # Check if run_id was passed from orchestrator (for shared correlation with cluster scan)
    # If not, generate a new one for standalone execution
    passed_run_id = json_.get("run_id")
    if passed_run_id:
        current_run_id = passed_run_id
        logger.info(f"Using run_id from orchestrator: {current_run_id}")
    else:
        current_run_id = get_current_run_id()
        logger.info(f"Generated new run_id for standalone execution: {current_run_id}")

    logger.info(f"TruffleHog scan starting for workspace: {workspace_id}, run_id: {current_run_id}")
    record_scan_started(workspace_id, current_run_id, "notebook_secret_scan")
    
    # Get time range for notebook search
    # Use environment variable TIME if provided, otherwise use config setting
    env_time = os.environ.get("TIME")
    if env_time:
        try:
            last_edited_after = convert_time_to_databricks_format(int(env_time))
            logger.info(f"Using provided TIME environment variable: {env_time}")
            time_filter_enabled = True
        except ValueError:
            logger.warning(f"Invalid TIME environment variable: {env_time}. Using default.")
            if Config.DAYS_BACK == 0:
                time_filter_enabled = False
            else:
                last_edited_after = get_yesterday_utc_midnight()
                time_filter_enabled = True
    else:
        # Check if days_back is 0 (scan all notebooks)
        if Config.DAYS_BACK == 0:
            time_filter_enabled = False
            logger.info(f"Scanning ALL notebooks (days_back = 0)")
        else:
            last_edited_after = get_yesterday_utc_midnight()
            time_filter_enabled = True
            logger.info(f"Using default time range: last {Config.DAYS_BACK} day(s)")
    
    # Initialize tracking variables
    results_list = []
    total_notebooks_processed = 0   # notebooks actually read and scanned
    total_notebooks_discovered = 0  # notebooks discovery returned
    total_secrets_found = 0
    notebooks_with_secrets = 0

    insert_stats.update({"attempted": 0, "written": 0, "failed": 0})
    skip_stats.update({"empty": 0, "non_text": 0})
    discovery_stats.update({"discovered": 0, "eligible": 0})
    filtered_reasons.clear()
    stale_stats.update({"stale_path": 0})
    object_events.clear()

    # Setup API request parameters
    url = f"{base_url}/api/2.0/search-midtier/unified-search"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "databricks-sat/0.1.0"}
    
    # Build filters - only include time filter if enabled
    filters = {"result_types": ["FILE", "NOTEBOOK"]}
    if time_filter_enabled:
        filters["last_edited_after"] = last_edited_after
    
    data = {
        "query": {"query": ""},
        "filters": filters,
        "page_size": Config.PAGE_SIZE,
    }
    
    if time_filter_enabled:
        print(f"📅 Searching for notebooks modified after: {datetime.fromtimestamp(last_edited_after/1000).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    else:
        print(f"📅 Searching for ALL notebooks (no time filter)")
    print(f"📄 Page size: {Config.PAGE_SIZE}")
    print()
    
    # Pagination loop
    next_page_token = ""  # Start with empty token
    page_number = 1
    
    try:
        while next_page_token is not None:
            print(f"📖 Processing page {page_number}...")

            # Add pagination token to request
            if next_page_token:
                data["page_token"] = next_page_token
            elif "page_token" in data:
                del data["page_token"]  # Remove token for first request

            # Make API request
            response, status_code = make_api_request(url, headers, data)

            # /search-midtier/unified-search rejects token-based auth on
            # workspaces where the endpoint is browser-only. See GitHub
            # issue #330. Fall back to /workspace/list-based discovery
            # so the scanner still produces a useful result. Only fall
            # back on the very first page — a mid-pagination 403 would
            # indicate a different problem and shouldn't silently switch
            # discovery strategies.
            if status_code == 403 and page_number == 1:
                logger.warning(
                    "unified-search rejected token auth (HTTP 403). "
                    "Falling back to workspace/list-based discovery. "
                    "Slower but works on workspaces where unified-search "
                    "is restricted to browser sessions."
                )
                print("⚠️  unified-search returned 403; using workspace/list fallback.")
                fallback_cutoff = last_edited_after if time_filter_enabled else None
                batch = discover_notebooks_via_workspace_list(time_filter_enabled, fallback_cutoff)
                logger.info(f"workspace/list discovered {len(batch)} notebooks/files")
                print(f"📂 workspace/list found {len(batch)} notebooks/files to scan")
                _process_notebook_batch(batch, results_list, Config.RESULTS_LOG_FILE,
                                        current_run_id, workspace_id)
                total_notebooks_discovered = len(batch)
                total_notebooks_processed = len(results_list)
                notebooks_with_secrets = sum(
                    1 for n in results_list if n.get("secrets_found", 0) > 0
                )
                total_secrets_found = sum(
                    n.get("secrets_found", 0) for n in results_list
                )
                break  # fallback is single-pass; leave the pagination loop

            if response is None:
                logger.warning(f"Failed to get response for page {page_number}")
                break
            
            # Record the pre-page length so per-page counters cover exactly the
            # notebooks this page contributed. Search can return more notebooks
            # than can be materialized (permissions or export failure), so
            # slicing by the search count would recount the previous page.
            page_start_time = time.time()
            results_before_page = len(results_list)
            page_skipped_before = skip_stats["empty"] + skip_stats["non_text"]
            page_filtered_before = discovery_stats["discovered"] - discovery_stats["eligible"]
            next_page_token = process_search_response(response, results_list, Config.RESULTS_LOG_FILE,
                                                     current_run_id, workspace_id)
            page_end_time = time.time()

            page_window = results_list[results_before_page:]
            page_notebooks = len(page_window)
            page_discovered = len(response.get("results", []))
            total_notebooks_processed += page_notebooks
            total_notebooks_discovered += page_discovered

            # Count secrets found in this page
            page_secrets = sum(1 for notebook in page_window if notebook.get("secrets_found", 0) > 0)
            page_total_secrets = sum(notebook.get("secrets_found", 0) for notebook in page_window)
            notebooks_with_secrets += page_secrets
            total_secrets_found += page_total_secrets

            page_skipped = (skip_stats["empty"] + skip_stats["non_text"]) - page_skipped_before
            page_filtered = (discovery_stats["discovered"] - discovery_stats["eligible"]) - page_filtered_before
            page_unread = page_discovered - page_notebooks - page_skipped - page_filtered
            if page_unread > 0:
                print(f"   ⚠️  Page {page_number}: {page_unread} of "
                      f"{page_discovered} notebook(s) could not be read (permissions or "
                      f"export failure) and were NOT scanned")

            # Only show page summary if secrets were found or if it's a significant milestone
            if page_total_secrets > 0:
                print(f"   ⚠️  Page {page_number}: {page_notebooks} notebooks processed, {page_total_secrets} secrets found in {page_secrets} notebook(s)")
            elif page_number % 10 == 0:  # Show progress every 10 pages
                print(f"   📖 Page {page_number}: {page_notebooks} notebooks processed (no secrets found)")
            
            print()
            
            page_number += 1

            # No unconditional inter-page sleep. Rate limiting is handled
            # reactively inside make_api_request(), which backs off and
            # retries only when the API actually returns HTTP 429.

        # Final summary
        print("🎉 Secret Scanning Completed!")
        print("=" * 60)
        total_skipped = skip_stats["empty"] + skip_stats["non_text"]
        # discovery_stats e a fonte unica: conta o bruto e o elegivel nas duas
        # rotas de descoberta, antes de qualquer export.
        total_discovered = discovery_stats["discovered"]
        total_eligible = discovery_stats["eligible"]
        total_filtered = total_discovered - total_eligible
        print(f"📊 Objects discovered: {total_discovered}")
        print(f"📊 Filtered out before scan (not source code): {total_filtered}")
        print(f"📊 Sent to scan: {total_eligible}")
        print(f"📊 Notebooks scanned: {total_notebooks_processed}")
        total_stale = stale_stats["stale_path"]
        if total_skipped > 0:
            print(f"📊 Skipped during scan (nothing to read): {total_skipped} "
                  f"({skip_stats['empty']} empty, {skip_stats['non_text']} binary)")
        if total_stale > 0:
            print(f"📊 Path changed since discovery (moved or removed): {total_stale}")
        if filtered_reasons:
            top = sorted(filtered_reasons.items(), key=lambda kv: -kv[1])
            resumo = ", ".join(f"{motivo}={qtd}" for motivo, qtd in top[:10])
            print(f"📊 Filter breakdown: {resumo}")
        print(f"🔍 Notebooks with secrets: {notebooks_with_secrets}")
        print(f"🚨 Total secrets detected: {total_secrets_found}")
        print(f"💾 Findings written to table: {insert_stats['written']} of {insert_stats['attempted']}")

        if notebooks_with_secrets > 0:
            print(f"⚠️  Security Alert: {notebooks_with_secrets} notebook(s) contain potential secrets!")
            print("   Please review the detailed results above and take appropriate action.")
        else:
            print("✅ No secrets detected in any notebooks. Great job!")

        print(f"📝 Detailed results logged to: {Config.RESULTS_LOG_FILE}")

        # A execucao parcial e um fato a registrar, nao um motivo para derrubar o
        # job. Reprovar em cima de excecao ja conhecida transforma o alarme em
        # ruido, e alarme ruidoso e alarme desligado. O veredito vai para
        # scan_discovery_stats.status e a leitura fica em v_secret_scan_completude,
        # onde a excecao ja tratada sai da conta do que exige acao.
        # Empty e binario nao entram: foram descobertos, mas nao tem texto para
        # ler. stale_path tambem sai — o objeto mudou de lugar entre a descoberta
        # e a leitura, e a proxima janela o alcanca no caminho novo.
        unscanned = max(0, total_eligible - total_notebooks_processed - total_skipped - total_stale)
        unwritten = max(0, insert_stats["attempted"] - insert_stats["written"])
        status = "INCOMPLETO" if (unscanned > 0 or unwritten > 0) else "COMPLETO"

        record_discovery_stats(workspace_id, current_run_id, "notebook_secret_scan",
                               total_discovered, total_filtered, total_eligible,
                               total_notebooks_processed, total_skipped, unscanned,
                               insert_stats["attempted"], unwritten, status)
        record_object_events(workspace_id, current_run_id, "notebook_secret_scan")

        # --- Insert a row if no secrets were found in any notebooks
        if total_secrets_found == 0:
            print("✅ No secrets found in any notebooks. Inserting a single tracking row for this run.")
            logger.info("No secrets found in any notebooks. Inserting a single row to track this run.")
            insert_no_secrets_tracking_row(workspace_id, current_run_id)

        if status == "INCOMPLETO":
            problems = []
            if unscanned > 0:
                problems.append(
                    f"{unscanned} of {total_eligible} eligible notebook(s) "
                    f"were not scanned (permissions, throttling, or export failure)"
                )
            if unwritten > 0:
                problems.append(
                    f"{unwritten} of {insert_stats['attempted']} finding(s) failed to persist"
                )
            message = "INCOMPLETE SCAN for workspace " + f"{workspace_id}: " + "; ".join(problems)
            print(f"⚠️  {message}")
            print("   Registrado em scan_discovery_stats.status. "
                  "Consulte v_secret_scan_completude para separar o que ja tem tratativa "
                  "do que continua PENDENTE.")
            logger.warning(message)
            # Perda de evidencia nao e excecao operacional: o segredo foi
            # encontrado e o registro se perdeu. Nenhuma tratativa cobre isso, e
            # por isso continua reprovando o job.
            if Config.FAIL_ON_INCOMPLETE or (unwritten > 0 and Config.FAIL_ON_LOST_FINDINGS):
                raise RuntimeError(message)
        else:
            print(f"✅ Scan completo: {total_notebooks_processed} de {total_eligible} elegiveis.")

        # Return summary statistics
        return {
            "total_notebooks": total_notebooks_processed,
            "notebooks_discovered": total_discovered,
            "notebooks_eligible": total_eligible,
            "objects_filtered": total_filtered,
            "objects_skipped": total_skipped,
            "objects_stale_path": total_stale,
            "notebooks_with_secrets": notebooks_with_secrets,
            "total_secrets": total_secrets_found,
            "findings_written": insert_stats["written"],
            "results": results_list
        }

    except KeyboardInterrupt:
        print("\n⏹️  Scanning interrupted by user")
        logger.info("Scanning workflow interrupted by user")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in scanning workflow: {str(e)}")
        print(f"❌ Error occurred during scanning: {str(e)}")
        raise

# Execute the scanning workflow
if __name__ == "__main__":
    scan_results = main_scanning_workflow()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: Results Analysis and Cleanup
# MAGIC
# MAGIC This cell provides additional analysis of the results and cleanup operations.

# COMMAND ----------

# Results Analysis and Cleanup

# Bound unconditionally: main_scanning_workflow() returns None on an interrupted
# scan, and the cleanup cell below reads this outside the guard.
notebooks_by_secrets = []

# Display scan results summary if available
if 'scan_results' in locals() and scan_results:
    print("📈 Detailed Scan Results Analysis")
    print("=" * 50)
    
    # Group results by secret type
    secret_types = {}
    for notebook in scan_results.get("results", []):
        if notebook.get("secrets_found", 0) > 0:
            for secret in notebook.get("secret_details", []):
                detector_name = secret.get("DetectorName", "Unknown")
                if detector_name not in secret_types:
                    secret_types[detector_name] = 0
                secret_types[detector_name] += 1
    
    if secret_types:
        print("🔍 Secret Types Detected:")
        for secret_type, count in sorted(secret_types.items()):
            print(f"   • {secret_type}: {count} occurrence(s)")
        print()
    
    # Show notebooks with most secrets
    notebooks_by_secrets = sorted(
        [nb for nb in scan_results.get("results", []) if nb.get("secrets_found", 0) > 0],
        key=lambda x: x.get("secrets_found", 0),
        reverse=True
    )
    
    if notebooks_by_secrets:
        print("📚 Top Notebooks with Secrets:")
        for i, notebook in enumerate(notebooks_by_secrets[:5]):  # Show top 5
            print(f"   {i+1}. {notebook.get('name', 'Unknown')} - {notebook.get('secrets_found', 0)} secret(s)")
        print()

# Cleanup and file operations
print("🧹 Cleanup Operations")
print("=" * 30)

# List temporary files created
print("📁 Temporary files in /tmp/notebooks:")

if notebooks_by_secrets:
    display(notebooks_by_secrets)
else:
    print("No notebooks with secrets to display.")



# COMMAND ----------

# MAGIC %sh ls -la /tmp/notebooks/ 2>/dev/null || echo "Directory not found or empty"

# COMMAND ----------

print("📄 Configuration files:")

# COMMAND ----------

# MAGIC %sh ls -la /tmp/trufflehog* 2>/dev/null || echo "No TruffleHog config files found"

# COMMAND ----------

print("📊 Results log file:")

# COMMAND ----------

# MAGIC %sh ls -la /tmp/trufflehog_scan_results.json 2>/dev/null || echo "No results log file found"

# COMMAND ----------

print("✅ Cleanup completed. Temporary files will be automatically removed when the cluster terminates.")

# Display final recommendations
print("\n🎯 Next Steps and Recommendations")
print("=" * 40)
print("1. 🔍 Review any detected secrets immediately")
print("2. 🔄 Rotate any exposed credentials")
print("3. 📝 Update notebooks to remove hardcoded secrets")
print("4. 🔐 Use Databricks secrets or environment variables instead")
print("5. 📅 Schedule regular secret scans as part of your security workflow")
print("6. 📋 Consider integrating this scan into your CI/CD pipeline")

if 'scan_results' in locals() and scan_results and scan_results.get("notebooks_with_secrets", 0) > 0:
    print("\n⚠️  IMMEDIATE ACTION REQUIRED:")
    print("   Secrets were detected in your notebooks. Please address them promptly!")
else:
    print("\n✅ No immediate action required - no secrets detected.")

# COMMAND ----------

print(f"TruffleHog Secret Scanner - {time.time() - start_time} seconds to run")
