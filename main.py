import datetime as dt
import json
import logging
import os
import urllib.error
import urllib.request


DISCORD_LIMIT = 2000  # Discord webhook message limit in characters.


def handle(request):
    """Entrypoint for the Cloud Function."""
    try:
        incident = _parse_request(request)
    except ValueError as exc:  # invalid payload
        logging.warning("Invalid request: %s", exc)
        return (str(exc), 400)

    webhook_url = os.getenv("WEBHOOK_URL")
    if not webhook_url:
        logging.error("WEBHOOK_URL environment variable is not set")
        return ("Webhook destination is not configured", 500)

    content = _build_message(incident)

    try:
        _post_to_discord(webhook_url, content)
    except RuntimeError as exc:
        logging.error("Failed to deliver webhook: %s", exc)
        return ("Failed to deliver incident", 502)

    return ("OK", 200)


def _parse_request(request):
    """Parse JSON payload from the incoming HTTP request."""
    try:
        body = request.get_json(force=True)
    except Exception as exc:  # pragma: no cover - defensive, depends on request impl.
        raise ValueError("Request body must be valid JSON") from exc

    if not isinstance(body, dict):
        raise ValueError("JSON payload must be an object")

    incident = body.get("incident")
    if not isinstance(incident, dict):
        raise ValueError("Payload must include an 'incident' object")

    return incident


def _build_message(incident):
    """Create a Discord-friendly message from the incident payload."""
    summary = incident.get("summary") or "(no summary)"
    severity = incident.get("severity") or "UNSPECIFIED"
    state = (incident.get("state") or "UNKNOWN").upper()
    policy_name = incident.get("policy_name") or "(no policy name)"
    condition = incident.get("condition_name") or "(no condition name)"
    resource_display = (
        incident.get("resource_display_name")
        or incident.get("resource_name")
        or (incident.get("resource", {}).get("labels", {}).get("instance_id"))
        or "(unknown resource)"
    )
    metric = incident.get("metric", {})
    metric_display = metric.get("displayName") or metric.get("type") or "(unknown metric)"

    started_at = _format_timestamp(incident.get("started_at"))
    ended_at = _format_timestamp(incident.get("ended_at"))

    lines = [
        f"**{summary}**",
        f"State: {state} | Severity: {severity}",
        f"Policy: {policy_name} | Condition: {condition}",
        f"Resource: {resource_display}",
        f"Metric: {metric_display}",
        f"Started: {started_at} | Ended: {ended_at}",
    ]

    observed_value = incident.get("observed_value")
    if observed_value:
        lines.append(f"Observed Value: {observed_value}")

    threshold_value = incident.get("threshold_value")
    if threshold_value:
        lines.append(f"Threshold: {threshold_value}")

    url = incident.get("url") or incident.get("apigee_url")
    if url:
        lines.append(f"Link: {url}")

    content = "\n".join(lines)
    if len(content) > DISCORD_LIMIT:
        content = content[: DISCORD_LIMIT - 3] + "..."

    return content


def _format_timestamp(timestamp_value):
    if timestamp_value in (None, ""):
        return "n/a"

    try:
        ts = float(timestamp_value)
        dt_value = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
        return dt_value.strftime("%Y-%m-%d %H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(timestamp_value)


def _post_to_discord(webhook_url, content):
    data = json.dumps({"content": content}).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            # Discord returns 204 No Content on success, other 2xx codes are ok too.
            if response.status >= 300:
                raise RuntimeError(f"Unexpected status from Discord: {response.status}")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Discord returned {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Discord connection failed: {exc.reason}") from exc

