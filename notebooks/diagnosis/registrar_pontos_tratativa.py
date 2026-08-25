# Databricks notebook source
# MAGIC %md
# MAGIC **Notebook name:** registrar_pontos_tratativa.
# MAGIC **Functionality:** semeia a tabela de tratativas com os pontos levantados que dependem de decisao do cliente.
# MAGIC
# MAGIC Os pontos entram com as colunas de decisao em branco. Quem preenche e o
# MAGIC cliente, por SQL ou pela interface que vier a existir. Enquanto `decisao`
# MAGIC estiver vazia, a view `v_pontos_tratativa` mostra o ponto como
# MAGIC AGUARDANDO DECISAO.
# MAGIC
# MAGIC Idempotente: rodar de novo nao duplica nem sobrescreve o que ja foi
# MAGIC preenchido. Um ponto ja decidido permanece como esta.

# COMMAND ----------

# MAGIC %run ../Includes/install_sat_sdk

# COMMAND ----------

# MAGIC %run ../Utils/initialize

# COMMAND ----------

# MAGIC %run ../Utils/common

# COMMAND ----------

create_scan_exception_dispositions_table()
schema = json_["analysis_schema_name"]

# COMMAND ----------

# Pontos levantados na validacao do canary em producao, 24/08/2026.
# (id, escopo, escopo_valor, outcome, observacao)
#
# A observacao carrega o que sabemos e o que ainda nao sabemos. O que nao
# sabemos fica escrito de proposito: apresentar uma causa que nao se sustenta e
# pior do que apresentar a duvida.
PONTOS = [
    ("EX-01", "pasta", "/Users/c1337546@interno.bb.com.br/.genie-workbench-deploy", "access_denied",
     "474 chamadas de get-status retornaram HTTP 403 na mesma pasta e janela em que 568 exports do mesmo SP "
     "tiveram sucesso; as pastas nao existem mais. Sao fontes geradas pelo instalador do Genie Workbench. "
     "Descartados: remocao, permissao de pasta, encoding e profundidade. Nao reproduzido. Severidade alta."),

    ("EX-02", "pasta", "/Users/antonio.ferreira.122@bb.com.br/.genie-workbench-deploy", "access_denied",
     "Mesmo caso do EX-01, na pasta do outro usuario. Tratar em conjunto."),

    ("EX-03", "objeto", "(a preencher com object_id)", None,
     "Segredo detectado em /corporativo/D2D/d2d1010_ingestodedados_finops_databricks/files/.databrickscfg, "
     "workspace 5248734954947264. Verificar se a credencial esta ativa (coluna verified) e quem e o dono. "
     "Severidade critica."),

    ("EX-04", "objeto", "(a preencher com object_id)", None,
     "Segredo detectado em /Users/joao.guidi@bb.com.br/var_env.env, workspace 5248734954947264. "
     "Verificar se a credencial esta ativa e se ha copias em outros locais. Severidade critica."),

    ("EX-05", "workspace", "629944503803736", None,
     "Workspace adb-ds-br-st-bb-uan-sln-mdl descoberto mas reprovado no teste de conexao "
     "(connection_test = False), por isso fora da analise. Definir se e permissao do SP ou indisponibilidade "
     "no momento do teste. Severidade media."),

    ("EX-06", "inventario", "total de workspaces da conta", None,
     "A descoberta encontrou 11 workspaces; a informacao previa do time era de 12. Confirmar o numero "
     "canonico e, havendo um a mais, por que nao aparece na listagem da conta. Severidade media."),

    ("EX-07", "processo", "cobertura da execucao incremental", None,
     "Na execucao incremental (days_back=1), 7 dos 10 workspaces retornaram zero objetos. A varredura "
     "completa revelou milhares, incluindo os arquivos com segredo. Definir periodicidade da varredura "
     "completa: mensal, trimestral ou sob demanda. Severidade media."),

    ("EX-08", "workspace", "4136692734632215", "export_failed",
     "11 falhas de export por esgotamento do backoff, em 4186 objetos elegiveis, sob 798 respostas de rate "
     "limit (0,26%). Avaliar se vale reduzir a concorrencia da varredura completa. Severidade baixa."),

    ("EX-09", "processo", "aviso e atribuicao de pendencias", None,
     "Nao existe processo para avisar o time quando surge pendencia, nem para atribuir responsavel. O SAT "
     "registra a evidencia; a integracao com o sistema de chamados do banco entra pela coluna "
     "referencia_externa. Definir quem e avisado, por qual canal e o prazo padrao por categoria. "
     "Severidade alta."),

    ("EX-10", "processo", "visibilidade de pastas pessoais", None,
     "Objetos em pastas pessoais ficaram fora do alcance do scanner sem gerar alerta. Definir se a politica "
     "admite conteudo de producao invisivel a ferramenta de seguranca, e quem decide isso. Severidade alta."),
]

# COMMAND ----------

def _lit(v):
    if v is None:
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


existentes = {
    r["disposition_id"]
    for r in spark.sql(f"SELECT disposition_id FROM {schema}.scan_exception_dispositions").collect()
}

novos = [p for p in PONTOS if p[0] not in existentes]

if not novos:
    print(f"Nenhum ponto novo: os {len(PONTOS)} ja estao registrados.")
else:
    valores = ",\n".join(
        f"({_lit(pid)}, {_lit(escopo)}, {_lit(valor)}, {_lit(outcome)}, "
        f"NULL, NULL, NULL, NULL, NULL, {_lit(obs)}, "
        f"'validacao canary 24/08/2026', current_timestamp(), true)"
        for pid, escopo, valor, outcome, obs in novos
    )
    spark.sql(f"""
        INSERT INTO {schema}.scan_exception_dispositions
        (disposition_id, escopo, escopo_valor, outcome, decisao, responsavel,
         referencia_externa, prazo, valido_ate, observacao, criado_por, criado_em, ativo)
        VALUES {valores}
    """)
    print(f"{len(novos)} ponto(s) registrado(s): {', '.join(p[0] for p in novos)}")
    print(f"{len(PONTOS) - len(novos)} ja existia(m) e nao foram tocados.")

# COMMAND ----------

create_scan_reporting_views()

# COMMAND ----------

display(spark.sql(f"""
    SELECT disposition_id, escopo, escopo_valor, situacao, objetos_afetados,
           decisao, responsavel, prazo, referencia_externa
    FROM {schema}.v_pontos_tratativa
    ORDER BY disposition_id
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Como o cliente preenche
# MAGIC
# MAGIC ```sql
# MAGIC UPDATE <schema>.scan_exception_dispositions
# MAGIC SET decisao = 'em_remediacao',
# MAGIC     responsavel = 'Nome do responsavel',
# MAGIC     referencia_externa = 'INC0012345',
# MAGIC     prazo = date'2026-09-15'
# MAGIC WHERE disposition_id = 'EX-03';
# MAGIC ```
# MAGIC
# MAGIC Valores aceitos em `decisao`: investigando, aguardando_acesso, em_remediacao,
# MAGIC aceito, falso_positivo, fora_de_escopo.
# MAGIC
# MAGIC `aceito` exige `valido_ate`: na data, o ponto volta a aparecer como
# MAGIC TRATATIVA VENCIDA. Aceite de risco sem prazo vira exceção permanente por
# MAGIC esquecimento.
