#!/usr/bin/env python3
"""Generate the Grafana dashboard JSON from the panel-per-statement SQL file.

The SQL file is the single source of truth: every panel is one statement
preceded by a `-- <title> | <view> | <unit>` header under a
`-- == Section ==` marker, and this script turns those headers into panels.
The only rewrite it applies is the service names -- `'stunnel-client'` and
`'stunnel-server'` become `'${client}'` and `'${server}'`, so the same panels
can read another deployment (the metrics a verification run publishes, for
instance).

  python3 tools/make_grafana_dashboard.py
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {
    "sql": ROOT / "docs/grafana-metrics.sql",
    "out": ROOT / "docs/grafana-metrics-dashboard.json",
    "title": "stunnel — tunnel telemetry",
    "uid": "stunnel-tunnel-telemetry",
    "description": "stunnel client and server telemetry, read from the OTel collector's "
                   "ClickHouse tables (database otel). Queries: docs/grafana-metrics.sql",
    "services": {
        "client": ("stunnel-client", "stunnel-client,stunnel-mock"),
        "server": ("stunnel-server", "stunnel-server,stunnel-mock"),
    },
    "time_from": "now-6h",
    "refresh": "1m",
    # Never below otel.export_interval_secs (15 in the sample config), or a
    # bucket has no second point to difference against.
    "min_interval": "15s",
    "tags": ["stunnel", "otel", "clickhouse"],
}

DATASOURCE = {"type": "grafana-clickhouse-datasource", "uid": "${datasource}"}


def parse_panels(text):
    """Panels in file order, each tagged with the `-- == Section ==` above it."""
    panels = []
    section = None
    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        title = None
        lines = []
        for line in chunk.splitlines():
            stripped = line.strip()
            if not lines and (not stripped or stripped.startswith("--")):
                if stripped.startswith("-- ==") and stripped.endswith("=="):
                    section = stripped.strip("-= ").strip()
                elif stripped.startswith("--") and "|" in line:
                    title = line.lstrip("- ").strip()
                continue
            lines.append(line)
        if not lines:
            continue
        if title is None:
            sys.exit(f"statement without a panel header: {lines[0][:60]}")
        parts = [p.strip() for p in title.split("|")]
        if len(parts) != 3:
            sys.exit(f"panel header needs <title> | <view> | <unit>: {title}")
        panels.append({"title": parts[0], "view": parts[1], "unit": parts[2],
                       "section": section, "sql": "\n".join(lines).strip()})
    if any(panel["section"] is None for panel in panels):
        sys.exit("every panel needs a `-- == Section ==` marker above it")
    return panels


def describe(sql):
    tables = sorted(set(re.findall(r"otel\.(otel_metrics_\w+)", sql)))
    metrics = set(re.findall(r"MetricName\s*=\s*'([^']+)'", sql))
    for group in re.findall(r"MetricName\s+IN\s*\(([^)]*)\)", sql):
        metrics.update(re.findall(r"'([^']+)'", group))
    parts = []
    if metrics:
        parts.append("Metrics: " + ", ".join(f"`{m}`" for m in sorted(metrics)))
    if tables:
        parts.append("Table: " + ", ".join(f"`{t}`" for t in tables))
    return " · ".join(parts)


def field_config(view, unit):
    if view == "barchart":
        return {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {
                    "axisPlacement": "auto",
                    "fillOpacity": 80,
                    "gradient": {"mode": "none"},
                    "lineWidth": 1,
                    "showValue": "auto",
                    "stacking": {"mode": "normal"},
                },
                "noValue": "0",
                "unit": unit,
            },
            "overrides": [],
        }
    if view == "stat":
        return {
            "defaults": {
                "color": {"mode": "thresholds"},
                "noValue": "0",
                "thresholds": {"mode": "absolute",
                               "steps": [{"color": "green", "value": None}]},
                "unit": unit,
            },
            "overrides": [],
        }
    return {
        "defaults": {
            "color": {"mode": "palette-classic"},
            "custom": {
                "axisPlacement": "auto",
                "drawStyle": "line",
                "fillOpacity": 10,
                "lineWidth": 2,
                "showPoints": "never",
                "spanNulls": False,
            },
            "noValue": "0",
            "unit": unit,
        },
        "overrides": [],
    }


def service_variable(name, label, default, options):
    return {
        "current": {"selected": True, "text": default, "value": default},
        "hide": 0,
        "includeAll": False,
        "label": label,
        "multi": False,
        "name": name,
        "options": [{"selected": value == default, "text": value, "value": value}
                    for value in options.split(",")],
        "query": options,
        "queryValue": "",
        "skipUrlSync": False,
        "type": "custom",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sql")
    parser.add_argument("--out")
    args = parser.parse_args()
    settings = dict(DEFAULTS)
    if args.sql:
        settings["sql"] = Path(args.sql)
    if args.out:
        settings["out"] = Path(args.out)
    sql_file, out_file = settings["sql"], settings["out"]

    panels = parse_panels(sql_file.read_text())
    parameterised = 0
    for panel in panels:
        for variable, (service, _) in settings["services"].items():
            panel["sql"], count = re.subn(rf"'{service}'", f"'${{{variable}}}'", panel["sql"])
            parameterised += count

    dashboard_panels = []
    panel_id = 1
    row_id = 100
    y = 0
    sections = []
    for panel in panels:
        if not sections or sections[-1][0] != panel["section"]:
            sections.append((panel["section"], []))
        sections[-1][1].append(panel)

    for row_title, row_panels in sections:
        dashboard_panels.append({
            "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
            "id": row_id,
            "panels": [],
            "title": row_title,
            "type": "row",
        })
        row_id += 1
        y += 1
        x = 0
        line_height = 0
        for panel in row_panels:
            is_stat = panel["view"] == "stat"
            width, height = (8, 6) if is_stat else (12, 8)
            if x + width > 24:
                x = 0
                y += line_height
                line_height = 0
            dashboard_panels.append({
                "datasource": DATASOURCE,
                "description": describe(panel["sql"]),
                "fieldConfig": field_config(panel["view"], panel["unit"]),
                "gridPos": {"h": height, "w": width, "x": x, "y": y},
                "id": panel_id,
                "options": {
                    "colorMode": "value",
                    "graphMode": "area",
                    "justificationMode": "auto",
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "",
                                      "values": False},
                    "textMode": "auto",
                } if is_stat else {
                    "legend": {"calcs": [], "displayMode": "list",
                               "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "none"},
                },
                "targets": [{
                    "datasource": DATASOURCE,
                    "editorType": "sql",
                    "format": 1 if is_stat else 0,
                    "rawSql": panel["sql"],
                    "refId": "A",
                }],
                "title": panel["title"],
                "type": panel["view"],
            })
            panel_id += 1
            x += width
            line_height = max(line_height, height)
        y += line_height

    templating = [{
        "current": {"selected": True, "text": "ClickHouse",
                    "value": "${DS_GRAFANA_CLICKHOUSE_DATASOURCE}"},
        "hide": 0,
        "includeAll": False,
        "label": "Data source",
        "multi": False,
        "name": "datasource",
        "options": [],
        "query": "grafana-clickhouse-datasource",
        "refresh": 1,
        "regex": "",
        "skipUrlSync": False,
        "type": "datasource",
    }]
    for variable, (default, options) in settings["services"].items():
        templating.append(
            service_variable(variable, variable.capitalize(), default, options))

    dashboard = {
        "__inputs": [{
            "name": "DS_GRAFANA_CLICKHOUSE_DATASOURCE",
            "label": "ClickHouse",
            "description": "",
            "type": "datasource",
            "pluginId": "grafana-clickhouse-datasource",
            "pluginName": "ClickHouse",
        }],
        "__requires": [
            {"type": "grafana", "id": "grafana", "name": "Grafana", "version": ">=11.0.0"},
            {"type": "datasource", "id": "grafana-clickhouse-datasource",
             "name": "ClickHouse", "version": "4.0.0"},
            {"type": "panel", "id": "barchart", "name": "Bar chart", "version": ""},
            {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
            {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
        ],
        "annotations": {"list": [{
            "builtIn": 1,
            "datasource": {"type": "grafana", "uid": "-- Grafana --"},
            "enable": True,
            "hide": True,
            "iconColor": "rgba(0, 211, 255, 1)",
            "name": "Annotations & Alerts",
            "type": "dashboard",
        }]},
        "description": settings["description"],
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "liveNow": False,
        "minInterval": settings["min_interval"],
        "panels": dashboard_panels,
        "refresh": settings["refresh"],
        "schemaVersion": 39,
        "tags": settings["tags"],
        "templating": {"list": templating},
        "time": {"from": settings["time_from"], "to": "now"},
        "timepicker": {},
        "timezone": "",
        "title": settings["title"],
        "uid": settings["uid"],
        "version": 1,
        "weekStart": "",
    }

    with open(out_file, "w") as handle:
        json.dump(dashboard, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(f"{out_file}: {len(panels)} panels, {len(sections)} rows, "
          f"{parameterised} service literals parameterised")


if __name__ == "__main__":
    main()
