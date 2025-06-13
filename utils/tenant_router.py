# utils/tenant_router.py

from utils.config_loader import load_multi_tenant_config

# Carrega configuração de tenants (cacheada na importação)
TENANTS_CONFIG = load_multi_tenant_config(path="config/sources_config.yaml")


def resolve_tenant(event_payload, source_name, rule_id):
    """
    Determina qual tenant (se algum) deve receber este evento baseado em:
    - source_name: nome da data source
    - rule_id: ID da regra de detecção
    - event_payload: payload completo do alerta, incluindo campos para filtros

    Retorna tupla (tenant_id, token) se houver correspondência, senão (None, None).
    """
    for tenant_id, tenant_data in TENANTS_CONFIG.items():
        ds_list = tenant_data.get("data_sources", []) or []

        # Encontra a fonte configurada e habilitada neste tenant
        ds_conf = next(
            (d for d in ds_list
             if d.get("name") == source_name and d.get("enabled", False)),
            None
        )
        if not ds_conf:
            continue

        # Verifica se a regra está permitida
        allowed_rules = ds_conf.get("event_types", []) or []
        if rule_id not in allowed_rules:
            continue

        # Aplica filtros configurados
        filters = ds_conf.get("filters") or {}
        if not _filters_match(event_payload, source_name, filters):
            continue

        # Encontrou tenant válido
        token = tenant_data.get("token")
        return tenant_id, token

    return None, None


def _filters_match(event_payload, source_name, filters):
    """
    Avalia filtros definidos para uma dada data source contra o payload.
    Retorna True se todos os filtros coincidirem, False caso contrário.
    Wildcard '*' em qualquer lista de valores faz o filtro passar automaticamente.
    """
    for key, values in filters.items():
        # Garante que values é uma lista
        if not isinstance(values, (list, tuple, set)):
            continue

        # Filtro de agent_ids para wazuh_alerts
        if source_name == "wazuh_alerts" and key == "agent_ids":
            agent = event_payload.get("agent", {}) or {}
            agent_id = agent.get("id")
            if "*" not in values and agent_id not in values:
                return False

        # Filtro de hostname para fontes linux*
        elif source_name.startswith("linux") and key == "hostname":
            hostname = event_payload.get("hostname")
            if "*" not in values and hostname not in values:
                return False

        # Filtro de sensor_ids para crowdstrike
        elif source_name == "crowdstrike" and key == "sensor_ids":
            sensor_id = event_payload.get("sensor_id")
            if "*" not in values and sensor_id not in values:
                return False

        # Filtro de organization_ids para Office365
        elif key == "organization_ids":
            org_id = (
                event_payload.get("data", {})
                .get("office365", {})
                .get("OrganizationId")
            )
            if "*" not in values and org_id not in values:
                return False

        # Se for um filtro desconhecido, simplesmente ignora

    return True
