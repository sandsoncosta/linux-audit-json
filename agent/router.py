"""
router.py — Avalia rotas e despacha eventos para os destinos corretos.

Lógica por rota:
  1. Cria FilterEngine temporário apenas com os filtros declarados na rota.
  2. Se action == "drop"  → evento descartado para ESTA rota.
  3. Se action == "tag"   → adiciona tag e continua.
  4. Se action == "allow" ou "pass" → envia para os destinos da rota.

Falha em um destino NÃO impede envio para os demais (RN-05).
"""

from config_loader import AgentConfig, RouteConfig
from filters import FilterEngine
from internal_logging import log
from models import AuditEvent


class Router:
    """Gerencia rotas e despacha eventos."""

    def __init__(
        self,
        config: AgentConfig,
        outputs: dict,
        filter_engine: FilterEngine,
    ):
        self._routes = config.routes
        self._all_filters = config.filters
        self._outputs = outputs
        self._filter_engine = filter_engine

        self.stats = {
            "received": 0,
            "dropped": 0,
            "sent": 0,
            "send_errors": 0,
        }

        log.info("Router inicializado com %d rota(s).", len(self._routes))

    def dispatch(self, event: AuditEvent) -> None:
        self.stats["received"] += 1
        for route in self._routes:
            self._apply_route(route, event)

    def _apply_route(self, route: RouteConfig, event: AuditEvent) -> None:
        # Monta engine apenas com filtros desta rota
        route_filters = {
            name: self._all_filters[name]
            for name in route.filters
            if name in self._all_filters
        }

        if route_filters:
            engine = FilterEngine(route_filters)
            action, matched = engine.evaluate(event)

            if action == "drop":
                self.stats["dropped"] += 1
                log.debug(
                    "Rota '%s': evento %s descartado por filtro '%s'.",
                    route.name, event.event_id, matched,
                )
                return

            if action == "tag" and matched:
                tag_val = self._all_filters[matched].tag
                if tag_val and tag_val not in event.tags:
                    event.tags.append(tag_val)

        event.route_name = route.name

        for dname in route.destinations:
            output = self._outputs.get(dname)
            if output is None:
                log.warning("Rota '%s': destino '%s' não encontrado.", route.name, dname)
                continue
            try:
                success = output.send(event)
                if success:
                    self.stats["sent"] += 1
                else:
                    self.stats["send_errors"] += 1
            except Exception as e:
                self.stats["send_errors"] += 1
                log.error(
                    "Rota '%s': erro ao enviar para destino '%s' — %s",
                    route.name, dname, e,
                )
