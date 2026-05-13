"""Pure filtering logic for QueryScanner (no Qt imports)."""


def format_query_client(query_row):
    """Format client_addr:client_port like QueryAnalyzerTab expects."""
    addr = query_row.get("client_addr")
    port = query_row.get("client_port")
    if addr and port:
        return f"{addr}:{port}"
    return ""


def apply_scanner_filters(queries, filters):
    """Pure filter logic shared with tests."""
    filtered = []

    state_filter = filters.get("state") or ""
    query_text_filter = filters.get("query_text") or ""
    application_filter = filters.get("application") or ""
    user_filter = filters.get("user") or ""
    client_filter = filters.get("client") or ""

    for query in queries:
        matches = True

        if state_filter:
            state = query.get("state", "").lower()
            if state_filter == "active" and state != "active":
                matches = False
            elif state_filter == "idle" and "idle" not in state:
                matches = False
            elif state_filter == "blocked" and state != "blocked":
                matches = False

        if matches and query_text_filter:
            query_text = query.get("query", "").lower()
            if query_text_filter not in query_text:
                matches = False

        if matches and application_filter:
            app_name = query.get("application_name", "").lower()
            if application_filter.lower() != app_name:
                matches = False

        if matches and user_filter:
            user = query.get("usename", "").lower()
            if user_filter.lower() != user:
                matches = False

        if matches and client_filter:
            client = format_query_client(query)
            if client_filter != client:
                matches = False

        if matches:
            filtered.append(query)

    return filtered
