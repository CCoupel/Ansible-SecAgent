# BACKLOG Ansible-SecAgent — Migré vers GitHub Issues

> **⚠️ Ce fichier est désormais archivé.**
> Le suivi des tâches est entièrement géré via **GitHub Issues**.

## 🔗 Liens directs

| Lien | Description |
|------|-------------|
| **[Toutes les issues](https://github.com/CCoupel/Ansible-SecAgent/issues)** | Vue complète du backlog |
| **[Issues ouvertes (à faire)](https://github.com/CCoupel/Ansible-SecAgent/issues?q=is%3Aopen)** | Tâches actives — Phase 10 |
| **[Issues fermées (terminées)](https://github.com/CCoupel/Ansible-SecAgent/issues?q=is%3Aclosed)** | Phases 1–9 complètes |
| **[Phase 10 — Enrollment Token](https://github.com/CCoupel/Ansible-SecAgent/issues?q=label%3Aphase%3A10-enrollment+is%3Aopen)** | Prochaine phase active |

---

## Vue d'ensemble des milestones

| Milestone | Status | Lien |
|-----------|--------|------|
| Phase 1 — secagent-minion | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/1?closed=1) |
| Phase 2 — secagent-server | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/2?closed=1) |
| Phase 3 — plugins Ansible | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/3?closed=1) |
| Phase 4 — Production Kubernetes | ⏸ SUSPENDU | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/4?closed=1) |
| Phase 5 — Hardening & Docs | ⏸ SUSPENDU | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/5?closed=1) |
| Phase 6 — Management CLI GO | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/6?closed=1) |
| Phase 7 — Server GO | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/7?closed=1) |
| Phase 8 — Agent GO | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/8?closed=1) |
| Phase 9 — Plugins GO | ✅ COMPLÈTE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/9?closed=1) |
| Phase 10 — Enrollment Token | 🆕 À FAIRE | [issues](https://github.com/CCoupel/Ansible-SecAgent/milestone/10) |

---

## Labels disponibles

### Par phase
`phase:1-minion` · `phase:2-server` · `phase:3-plugins` · `phase:4-k8s` · `phase:5-hardening` · `phase:6-cli` · `phase:7-server-go` · `phase:8-agent-go` · `phase:9-plugins-go` · `phase:10-enrollment`

### Par statut
`status:todo` · `status:completed` · `status:suspended` · `status:obsolete`

### Par propriétaire
`owner:dev-agent` · `owner:dev-relay` · `owner:dev-plugins` · `owner:test-writer` · `owner:qa` · `owner:security` · `owner:deploy-qualif` · `owner:deploy-prod` · `owner:cdp`

### Par type
`type:implementation` · `type:test` · `type:qa` · `type:security` · `type:deploy` · `type:validation`

---

## Correspondance numéros backlog → issues GitHub

| Backlog | GitHub Issue | Titre |
|---------|-------------|-------|
| #4 | [#1](https://github.com/CCoupel/Ansible-SecAgent/issues/1) | facts_collector.py |
| #6 | [#2](https://github.com/CCoupel/Ansible-SecAgent/issues/2) | secagent_agent.py — enrollment RSA-4096 |
| #8 | [#3](https://github.com/CCoupel/Ansible-SecAgent/issues/3) | secagent_agent.py — connexion WSS |
| #9 | [#4](https://github.com/CCoupel/Ansible-SecAgent/issues/4) | dispatcher messages WS |
| #11 | [#5](https://github.com/CCoupel/Ansible-SecAgent/issues/5) | exec_command subprocess |
| #13 | [#6](https://github.com/CCoupel/Ansible-SecAgent/issues/6) | put_file |
| #14 | [#7](https://github.com/CCoupel/Ansible-SecAgent/issues/7) | fetch_file |
| #15 | [#8](https://github.com/CCoupel/Ansible-SecAgent/issues/8) | async_registry.py |
| #17 | [#9](https://github.com/CCoupel/Ansible-SecAgent/issues/9) | systemd service |
| #19 | [#10](https://github.com/CCoupel/Ansible-SecAgent/issues/10) | Tests Phase 1 |
| #20 | [#11](https://github.com/CCoupel/Ansible-SecAgent/issues/11) | QA Phase 1 |
| #22 | [#12](https://github.com/CCoupel/Ansible-SecAgent/issues/12) | Security review Phase 1 |
| #23 | [#13](https://github.com/CCoupel/Ansible-SecAgent/issues/13) | Deploy qualif Phase 1 |
| #24 | [#14](https://github.com/CCoupel/Ansible-SecAgent/issues/14) | agent_store.py SQLite |
| #25 | [#15](https://github.com/CCoupel/Ansible-SecAgent/issues/15) | routes_register.py |
| #26 | [#16](https://github.com/CCoupel/Ansible-SecAgent/issues/16) | ws_handler.py |
| #27 | [#17](https://github.com/CCoupel/Ansible-SecAgent/issues/17) | nats_client.py |
| #28 | [#18](https://github.com/CCoupel/Ansible-SecAgent/issues/18) | routes_exec.py |
| #29 | [#19](https://github.com/CCoupel/Ansible-SecAgent/issues/19) | main.py FastAPI |
| #30 | [#20](https://github.com/CCoupel/Ansible-SecAgent/issues/20) | docker-compose.yml |
| #31 | [#21](https://github.com/CCoupel/Ansible-SecAgent/issues/21) | Tests Phase 2 |
| #32 | [#22](https://github.com/CCoupel/Ansible-SecAgent/issues/22) | QA Phase 2 |
| #33 | [#23](https://github.com/CCoupel/Ansible-SecAgent/issues/23) | Security review Phase 2 |
| #34 | [#24](https://github.com/CCoupel/Ansible-SecAgent/issues/24) | Deploy qualif Phase 2 |
| #35 | [#25](https://github.com/CCoupel/Ansible-SecAgent/issues/25) | connection plugin secagent.py |
| #36 | [#26](https://github.com/CCoupel/Ansible-SecAgent/issues/26) | inventory plugin (OBSOLÈTE) |
| #37 | [#27](https://github.com/CCoupel/Ansible-SecAgent/issues/27) | Tests Phase 3 |
| #38 | [#28](https://github.com/CCoupel/Ansible-SecAgent/issues/28) | QA Phase 3 |
| #39 | [#29](https://github.com/CCoupel/Ansible-SecAgent/issues/29) | Security review global |
| #40 | [#30](https://github.com/CCoupel/Ansible-SecAgent/issues/30) | Deploy qualif Phase 3 |
| #41 | [#31](https://github.com/CCoupel/Ansible-SecAgent/issues/31) | Deploy prod Phase 3 (SUSPENDU) |
| #42 | [#32](https://github.com/CCoupel/Ansible-SecAgent/issues/32) | Helm chart structure |
| #43 | [#33](https://github.com/CCoupel/Ansible-SecAgent/issues/33) | Helm StatefulSet NATS |
| #44 | [#34](https://github.com/CCoupel/Ansible-SecAgent/issues/34) | Helm Deployment server |
| #45 | [#35](https://github.com/CCoupel/Ansible-SecAgent/issues/35) | Helm DaemonSet minion |
| #46 | [#36](https://github.com/CCoupel/Ansible-SecAgent/issues/36) | Helm ConfigMap + Secrets |
| #47 | [#37](https://github.com/CCoupel/Ansible-SecAgent/issues/37) | Helm Ingress |
| #48 | [#38](https://github.com/CCoupel/Ansible-SecAgent/issues/38) | Helm Service |
| #49 | [#39](https://github.com/CCoupel/Ansible-SecAgent/issues/39) | Helm PVC |
| #50 | [#40](https://github.com/CCoupel/Ansible-SecAgent/issues/40) | Helm tests |
| #51 | [#41](https://github.com/CCoupel/Ansible-SecAgent/issues/41) | Helm deploy script |
| #52 | [#42](https://github.com/CCoupel/Ansible-SecAgent/issues/42) | Helm documentation |
| #53 | [#43](https://github.com/CCoupel/Ansible-SecAgent/issues/43) | Deploy prod Phase 4 |
| #54 | [#44](https://github.com/CCoupel/Ansible-SecAgent/issues/44) | Runbooks prod |
| #55 | [#45](https://github.com/CCoupel/Ansible-SecAgent/issues/45) | Monitoring Prometheus/Grafana |
| #56 | [#46](https://github.com/CCoupel/Ansible-SecAgent/issues/46) | Hardening sécurité |
| #57 | [#47](https://github.com/CCoupel/Ansible-SecAgent/issues/47) | Disaster recovery |
| #58 | [#48](https://github.com/CCoupel/Ansible-SecAgent/issues/48) | Performance tuning |
| #59 | [#49](https://github.com/CCoupel/Ansible-SecAgent/issues/49) | Migration guide |
| #60 | [#50](https://github.com/CCoupel/Ansible-SecAgent/issues/50) | SLA & Support |
| #61 | [#51](https://github.com/CCoupel/Ansible-SecAgent/issues/51) | MVP Final Review & Sign-off |
| #62 | [#52](https://github.com/CCoupel/Ansible-SecAgent/issues/52) | Endpoints admin |
| #63 | [#53](https://github.com/CCoupel/Ansible-SecAgent/issues/53) | DB server_config + RSA keypair |
| #64 | [#54](https://github.com/CCoupel/Ansible-SecAgent/issues/54) | Rotation clefs JWT |
| #65 | [#55](https://github.com/CCoupel/Ansible-SecAgent/issues/55) | Agent handler rekey |
| #66 | [#56](https://github.com/CCoupel/Ansible-SecAgent/issues/56) | CLI cobra |
| #67 | [#57](https://github.com/CCoupel/Ansible-SecAgent/issues/57) | Tests GO CLI |
| #68 | [#58](https://github.com/CCoupel/Ansible-SecAgent/issues/58) | QA Phase 6 |
| #69 | [#59](https://github.com/CCoupel/Ansible-SecAgent/issues/59) | Deploy qualif Phase 6 |
| #70 | [#60](https://github.com/CCoupel/Ansible-SecAgent/issues/60) | Specs GO server |
| #71 | [#61](https://github.com/CCoupel/Ansible-SecAgent/issues/61) | Server main.go |
| #72 | [#62](https://github.com/CCoupel/Ansible-SecAgent/issues/62) | handlers/register.go |
| #73 | [#63](https://github.com/CCoupel/Ansible-SecAgent/issues/63) | handlers/exec.go |
| #74 | [#64](https://github.com/CCoupel/Ansible-SecAgent/issues/64) | handlers/inventory.go |
| #75 | [#65](https://github.com/CCoupel/Ansible-SecAgent/issues/65) | ws/handler.go |
| #76 | [#66](https://github.com/CCoupel/Ansible-SecAgent/issues/66) | storage/agent_store.go |
| #77 | [#67](https://github.com/CCoupel/Ansible-SecAgent/issues/67) | broker/nats.go |
| #78 | [#68](https://github.com/CCoupel/Ansible-SecAgent/issues/68) | Tests GO server |
| #79 | [#69](https://github.com/CCoupel/Ansible-SecAgent/issues/69) | Migration Python→GO |
| #80 | [#70](https://github.com/CCoupel/Ansible-SecAgent/issues/70) | QA Phase 7 |
| #81 | [#71](https://github.com/CCoupel/Ansible-SecAgent/issues/71) | Deploy qualif Phase 7 |
| #82 | [#72](https://github.com/CCoupel/Ansible-SecAgent/issues/72) | Agent architecture GO |
| #83 | [#73](https://github.com/CCoupel/Ansible-SecAgent/issues/73) | agent/main.go |
| #84 | [#74](https://github.com/CCoupel/Ansible-SecAgent/issues/74) | agent/dispatcher.go |
| #85 | [#75](https://github.com/CCoupel/Ansible-SecAgent/issues/75) | agent/executor.go |
| #86 | [#76](https://github.com/CCoupel/Ansible-SecAgent/issues/76) | agent/files.go |
| #87 | [#77](https://github.com/CCoupel/Ansible-SecAgent/issues/77) | agent/registry.go |
| #88 | [#78](https://github.com/CCoupel/Ansible-SecAgent/issues/78) | agent/facts.go |
| #89 | [#79](https://github.com/CCoupel/Ansible-SecAgent/issues/79) | Tests GO agent |
| #90 | [#80](https://github.com/CCoupel/Ansible-SecAgent/issues/80) | QA Phase 8 |
| #91 | [#81](https://github.com/CCoupel/Ansible-SecAgent/issues/81) | Deploy qualif Phase 8 |
| #92 | [#82](https://github.com/CCoupel/Ansible-SecAgent/issues/82) | inventory-wrapper/main.go |
| #93 | [#83](https://github.com/CCoupel/Ansible-SecAgent/issues/83) | inventory-wrapper/inventory.go |
| #94 | [#84](https://github.com/CCoupel/Ansible-SecAgent/issues/84) | exec-wrapper/main.go |
| #95 | [#85](https://github.com/CCoupel/Ansible-SecAgent/issues/85) | Tests integration GO wrappers |
| #96 | [#86](https://github.com/CCoupel/Ansible-SecAgent/issues/86) | Deploy qualif Phase 9 |
| #97 | [#87](https://github.com/CCoupel/Ansible-SecAgent/issues/87) | Store enrollment_tokens |
| #98 | [#88](https://github.com/CCoupel/Ansible-SecAgent/issues/88) | Store plugin_tokens |
| #99 | [#89](https://github.com/CCoupel/Ansible-SecAgent/issues/89) | Server RegisterAgent refactor |
| #100 | [#90](https://github.com/CCoupel/Ansible-SecAgent/issues/90) | Endpoints admin tokens |
| #101 | [#91](https://github.com/CCoupel/Ansible-SecAgent/issues/91) | Plugin token CIDR + regexp |
| #102 | [#92](https://github.com/CCoupel/Ansible-SecAgent/issues/92) | Agent enrollment token |
| #103 | [#93](https://github.com/CCoupel/Ansible-SecAgent/issues/93) | CLI tokens commands |
| #104 | [#94](https://github.com/CCoupel/Ansible-SecAgent/issues/94) | Tests GO enrollment tokens |
| #105 | [#95](https://github.com/CCoupel/Ansible-SecAgent/issues/95) | QA Phase 10 |
| #106 | [#96](https://github.com/CCoupel/Ansible-SecAgent/issues/96) | Deploy qualif Phase 10 |

---

## Comment ajouter de nouvelles issues

Les nouvelles tâches doivent être créées directement dans [GitHub Issues](https://github.com/CCoupel/Ansible-SecAgent/issues/new).

Utiliser les labels appropriés :
- `phase:N-xxx` pour associer à une phase
- `status:todo` pour les nouvelles tâches
- `owner:xxx` pour l'assignation
- `type:xxx` pour la nature de la tâche

Le CDP et les agents doivent consulter les issues GitHub en temps réel via l'API :
```
GET https://api.github.com/repos/CCoupel/Ansible-SecAgent/issues?state=open
```
