
# Benchmark and Workflow Backlog

Ordered roadmap for `benchmark-2node-signed` and follow-on branches.

1. **Run 2-node internet signed UDP benchmark**.
2. **Add real signed-packet benchmark payloads** closer to validator ingress behavior.
3. **Add benchmark summary parser** for tx/rx CSV outputs.
4. **Add 3-node fanout benchmark**.
5. **Add 5- or 6-node geographic benchmark**.
6. **Add Prometheus/Grafana observability** for benchmark runs.
7. **Only later investigate AF_XDP/DPDK** once baseline UDP path is measured and repeatable.

## Notes

- Keep each backlog item in a separate small branch when practical.
- Attach benchmark artifacts (CSV/JSON/logs) to PRs that make performance claims.
- Do not claim production readiness.

