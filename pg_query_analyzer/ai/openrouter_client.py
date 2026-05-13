"""OpenRouter helpers for settings validation and plan explanations."""

import json
import os
import ssl
from urllib import error, request

try:
    import certifi
except Exception:  # pragma: no cover - optional dependency at runtime
    certifi = None


def _normalize_base_url(base_url):
    return (base_url or "https://openrouter.ai/api/v1").rstrip("/")


def validate_openrouter_settings(base_url, api_key, model, timeout_seconds=12):
    """Validate OpenRouter key/model by issuing a tiny chat completion request."""
    url = f"{_normalize_base_url(base_url)}/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "temperature": 0,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, data=body, headers=headers, method="POST")
    ssl_context = _build_ssl_context()

    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
        choices = parsed.get("choices")
        if isinstance(choices, list) and choices:
            return True, "Подключение к OpenRouter успешно. Ключ и модель валидны."
        return False, "OpenRouter ответил, но формат ответа неожиданный (нет choices)."
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        return False, f"Ошибка OpenRouter ({exc.code}): {reason}"
    except error.URLError as exc:
        return False, _urlopen_network_message(exc, "Сетевая ошибка при подключении к OpenRouter")
    except ssl.SSLError as exc:
        return False, _ssl_error_hint(exc)
    except TimeoutError:
        return False, "Таймаут при проверке OpenRouter. Попробуйте позже."
    except Exception as exc:  # pragma: no cover - defensive fallback
        return False, f"Не удалось проверить OpenRouter: {exc}"


def list_openrouter_models(base_url, api_key, timeout_seconds=20):
    """Return a sorted list of available model IDs from OpenRouter."""
    url = f"{_normalize_base_url(base_url)}/models"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, headers=headers, method="GET")
    ssl_context = _build_ssl_context()
    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
        data = parsed.get("data")
        if not isinstance(data, list):
            raise RuntimeError("OpenRouter вернул неожиданный формат /models.")
        models = []
        for item in data:
            if not isinstance(item, dict):
                continue
            model_id = str(item.get("id") or "").strip()
            if model_id:
                models.append(model_id)
        models = sorted(set(models))
        if not models:
            raise RuntimeError("Список моделей пуст.")
        return models
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        raise RuntimeError(f"Ошибка OpenRouter ({exc.code}): {reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(
            _urlopen_network_message(exc, "Сетевая ошибка при загрузке списка моделей")
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(_ssl_error_hint(exc)) from exc


def generate_plan_explanation_openrouter(
    *,
    base_url,
    api_key,
    model,
    plan_payload,
    timeout_seconds=40,
):
    """Generate plan explanation and try to parse schema-first JSON."""
    url = f"{_normalize_base_url(base_url)}/chat/completions"
    system_prompt = (
        "Ты senior PostgreSQL performance engineer. "
        "Отвечай по-русски. "
        "На основе переданных данных плана дай практичную интерпретацию. "
        "Верни JSON строго по схеме: "
        "{"
        "\"summary\": string, "
        "\"key_findings\": [{\"severity\":\"high|medium|low\",\"title\":string,\"evidence\":string}], "
        "\"actions\": [{\"priority\":\"P1|P2|P3\",\"action\":string,\"why\":string}], "
        "\"confidence\": number"
        "}. "
        "Пиши без выдуманных метрик и без SQL, если его нет во входе. "
        "Если данных мало, всё равно верни валидный JSON с пустыми списками."
    )
    user_prompt = (
        "Сформируй объяснение плана для разработчика.\n"
        "Данные плана (JSON):\n"
        + json.dumps(plan_payload, ensure_ascii=False, default=str)
    )
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, data=body, headers=headers, method="POST")
    ssl_context = _build_ssl_context()

    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        raise RuntimeError(f"Ошибка OpenRouter ({exc.code}): {reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(
            _urlopen_network_message(exc, "Сетевая ошибка при подключении к OpenRouter")
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(_ssl_error_hint(exc)) from exc
    except TimeoutError as exc:
        raise RuntimeError("Таймаут запроса в OpenRouter") from exc

    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenRouter вернул пустой ответ (choices отсутствует).")
    message = (choices[0].get("message") or {}).get("content") or ""
    text = str(message).strip()
    if not text:
        raise RuntimeError("OpenRouter не вернул текст интерпретации.")
    return {
        "raw_text": text,
        "structured": _parse_structured_ai_response(text),
    }


def _extract_error_message(raw_response):
    if not raw_response:
        return ""
    try:
        parsed = json.loads(raw_response)
    except Exception:
        return raw_response[:240]

    error_obj = parsed.get("error")
    if isinstance(error_obj, dict):
        message = error_obj.get("message")
        if message:
            return str(message)
    message = parsed.get("message")
    return str(message) if message else raw_response[:240]


def _parse_structured_ai_response(text):
    if not text:
        return None
    stripped = text.strip()
    candidate = stripped
    if "```" in stripped:
        chunks = stripped.split("```")
        for chunk in chunks:
            cleaned = chunk.strip()
            if cleaned.startswith("{") and cleaned.endswith("}"):
                candidate = cleaned
                break
            if cleaned.startswith("json"):
                maybe = cleaned[4:].strip()
                if maybe.startswith("{") and maybe.endswith("}"):
                    candidate = maybe
                    break
    if not (candidate.startswith("{") and candidate.endswith("}")):
        return None
    try:
        parsed = json.loads(candidate)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    summary = parsed.get("summary")
    key_findings = parsed.get("key_findings")
    actions = parsed.get("actions")
    confidence = parsed.get("confidence")
    if not isinstance(summary, str):
        return None
    if not isinstance(key_findings, list):
        return None
    if not isinstance(actions, list):
        return None
    if not isinstance(confidence, (int, float)):
        return None
    return parsed


def mask_sql_literals(sql_text: str) -> str:
    if not sql_text:
        return ""
    masked = json.dumps(sql_text)[1:-1]  # normalize escapes consistently
    masked = masked.replace("\\n", "\n")
    # Replace single-quoted strings and standalone numeric literals.
    import re

    masked = re.sub(r"'(?:''|[^'])*'", "'***'", masked)
    masked = re.sub(r"\b\d+(?:\.\d+)?\b", "?", masked)
    return masked


def generate_workload_prioritization_openrouter(
    *,
    base_url,
    api_key,
    model,
    workload_payload,
    timeout_seconds=45,
):
    """Build P1/P2/P3 prioritization for workload rows."""
    url = f"{_normalize_base_url(base_url)}/chat/completions"
    system_prompt = (
        "Ты senior PostgreSQL performance engineer. "
        "Отвечай по-русски. "
        "Верни JSON строго по схеме: "
        "{"
        "\"summary\": string, "
        "\"priorities\": [{"
        "\"priority\":\"P1|P2|P3\","
        "\"queryid\":string,"
        "\"fingerprint\":string,"
        "\"reason\":string,"
        "\"first_check\":string"
        "}], "
        "\"quick_wins\": [string]"
        "}. "
        "Ранжируй по impact и вероятности проблемы. "
        "Не выдумывай метрики, опирайся только на вход."
    )
    user_prompt = (
        "Сформируй AI-приоритизацию workload (что чинить сначала):\n"
        + json.dumps(workload_payload, ensure_ascii=False, default=str)
    )
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, data=body, headers=headers, method="POST")
    ssl_context = _build_ssl_context()

    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        raise RuntimeError(f"Ошибка OpenRouter ({exc.code}): {reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(
            _urlopen_network_message(exc, "Сетевая ошибка при подключении к OpenRouter")
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(_ssl_error_hint(exc)) from exc
    except TimeoutError as exc:
        raise RuntimeError("Таймаут запроса в OpenRouter") from exc

    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenRouter вернул пустой ответ (choices отсутствует).")
    message = (choices[0].get("message") or {}).get("content") or ""
    text = str(message).strip()
    if not text:
        raise RuntimeError("OpenRouter не вернул текст workload-приоритизации.")
    return {
        "raw_text": text,
        "structured": _parse_workload_structured_response(text),
    }


def _parse_workload_structured_response(text):
    if not text:
        return None
    stripped = text.strip()
    candidate = stripped
    if "```" in stripped:
        chunks = stripped.split("```")
        for chunk in chunks:
            cleaned = chunk.strip()
            if cleaned.startswith("{") and cleaned.endswith("}"):
                candidate = cleaned
                break
            if cleaned.startswith("json"):
                maybe = cleaned[4:].strip()
                if maybe.startswith("{") and maybe.endswith("}"):
                    candidate = maybe
                    break
    if not (candidate.startswith("{") and candidate.endswith("}")):
        return None
    try:
        parsed = json.loads(candidate)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if not isinstance(parsed.get("summary"), str):
        return None
    if not isinstance(parsed.get("priorities"), list):
        return None
    if not isinstance(parsed.get("quick_wins"), list):
        return None
    return parsed


def generate_active_queries_triage_openrouter(
    *,
    base_url,
    api_key,
    model,
    active_queries_payload,
    timeout_seconds=45,
):
    """Generate incident triage for active queries and waits."""
    url = f"{_normalize_base_url(base_url)}/chat/completions"
    system_prompt = (
        "Ты senior PostgreSQL incident responder. "
        "Отвечай по-русски. "
        "Верни JSON строго по схеме: "
        "{"
        "\"summary\": string, "
        "\"incident_level\":\"low|medium|high\", "
        "\"blocking_candidates\": [{\"pid\":string,\"reason\":string}], "
        "\"actions\": [{\"priority\":\"P1|P2|P3\",\"action\":string,\"risk\":string}]"
        "}. "
        "Используй только данные входа, без выдумок."
    )
    user_prompt = (
        "Сделай triage по активным запросам PostgreSQL:\n"
        + json.dumps(active_queries_payload, ensure_ascii=False, default=str)
    )
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, data=body, headers=headers, method="POST")
    ssl_context = _build_ssl_context()
    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        raise RuntimeError(f"Ошибка OpenRouter ({exc.code}): {reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(
            _urlopen_network_message(exc, "Сетевая ошибка при подключении к OpenRouter")
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(_ssl_error_hint(exc)) from exc
    except TimeoutError as exc:
        raise RuntimeError("Таймаут запроса в OpenRouter") from exc

    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenRouter вернул пустой ответ (choices отсутствует).")
    message = (choices[0].get("message") or {}).get("content") or ""
    text = str(message).strip()
    if not text:
        raise RuntimeError("OpenRouter не вернул текст triage.")
    return {"raw_text": text, "structured": _parse_active_triage_response(text)}


def _parse_active_triage_response(text):
    if not text:
        return None
    stripped = text.strip()
    candidate = stripped
    if "```" in stripped:
        chunks = stripped.split("```")
        for chunk in chunks:
            cleaned = chunk.strip()
            if cleaned.startswith("{") and cleaned.endswith("}"):
                candidate = cleaned
                break
            if cleaned.startswith("json"):
                maybe = cleaned[4:].strip()
                if maybe.startswith("{") and maybe.endswith("}"):
                    candidate = maybe
                    break
    if not (candidate.startswith("{") and candidate.endswith("}")):
        return None
    try:
        parsed = json.loads(candidate)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if not isinstance(parsed.get("summary"), str):
        return None
    if not isinstance(parsed.get("incident_level"), str):
        return None
    if not isinstance(parsed.get("blocking_candidates"), list):
        return None
    if not isinstance(parsed.get("actions"), list):
        return None
    return parsed


def generate_workload_digest_openrouter(
    *,
    base_url,
    api_key,
    model,
    workload_payload,
    timeout_seconds=50,
):
    """Generate a concise markdown digest for workload operations."""
    url = f"{_normalize_base_url(base_url)}/chat/completions"
    system_prompt = (
        "Ты senior PostgreSQL performance engineer. "
        "Отвечай на русском в Markdown. "
        "Сделай короткий operational digest: Summary, Top risks, Immediate checks (safe/read-only), Next actions."
    )
    user_prompt = (
        "Подготовь digest по workload pg_stat_statements:\n"
        + json.dumps(workload_payload, ensure_ascii=False, default=str)
    )
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, data=body, headers=headers, method="POST")
    ssl_context = _build_ssl_context()
    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        raise RuntimeError(f"Ошибка OpenRouter ({exc.code}): {reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(
            _urlopen_network_message(exc, "Сетевая ошибка при подключении к OpenRouter")
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(_ssl_error_hint(exc)) from exc
    except TimeoutError as exc:
        raise RuntimeError("Таймаут запроса в OpenRouter") from exc

    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenRouter вернул пустой ответ (choices отсутствует).")
    message = (choices[0].get("message") or {}).get("content") or ""
    text = str(message).strip()
    if not text:
        raise RuntimeError("OpenRouter не вернул digest.")
    return text


def generate_postgres_tuning_recommendations_openrouter(
    *,
    base_url,
    api_key,
    model,
    postgres_profile_payload,
    timeout_seconds=55,
):
    """Generate personalized PostgreSQL tuning recommendations from server profile."""
    url = f"{_normalize_base_url(base_url)}/chat/completions"
    system_prompt = (
        "Ты senior PostgreSQL DBA/performance engineer. Отвечай по-русски.\n"
        "Вход: JSON-профиль (server_info, settings, db_stats, activity_states, top_statements, "
        "опционально hardware_via_ssh). Нет других источников — не придумывай значения и не ссылайся на метрики, "
        "которых нет во входе.\n"
        "Обязательно: в первых предложениях summary укажи версию PostgreSQL из server_info (если есть) "
        "и текущую базу по контексту профиля.\n"
        "Каждая рекомендация должна явно опираться на поля JSON: укажи имена параметров (settings.*) "
        "и/или наблюдаемые числа (db_stats.*, top_statements.*, activity_states). "
        "Если для вывода не хватает данных — так и напиши в details и предложи read_only_checks, "
        "которые соберут недостающее (только SELECT/show из каталога).\n"
        "hardware_via_ssh: учитывай RAM/CPU/диск для памяти, parallel_workers, I/O; если есть caveat — "
        "не утверждай, что это железо хоста PostgreSQL, если SSH-узел может быть bastion.\n"
        "Верни один JSON-объект строго по схеме:\n"
        "{"
        "\"summary\": string, "
        "\"recommendations\": [{\"priority\":\"P1|P2|P3\",\"title\":string,\"details\":string}], "
        "\"risks\": [string], "
        "\"read_only_checks\": [string], "
        "\"confidence\": number"
        "}\n"
        "Требования к содержанию: "
        "summary — 4–10 предложений с главным выводом и упоминанием 2–4 ключевых фактов из входа; "
        "recommendations — минимум 3 пункта, если во входе достаточно сигналов (иначе меньше, но честно); "
        "сортируй: сначала все P1, затем P2, затем P3; "
        "risks — побочные эффекты изменений и риск ошибочной интерпретации неполных данных; "
        "read_only_checks — 3–8 конкретных SQL или SHOW (одна строка на пункт), привязанных к сомнениям из summary; "
        "confidence — число 0..1, снизь, если мало метрик или нет hardware.\n"
        "Если данных мало — валидный JSON, пустые списки где уместно, summary объясняет нехватку данных."
    )
    user_prompt = (
        "Ниже JSON-профиль PostgreSQL (единственный источник истины для ответа). "
        "Ключи верхнего уровня: server_info, settings (map name→setting/unit/desc), db_stats, activity_states, "
        "pg_stat_statements_installed, top_statements (если расширение есть), hardware_via_ssh (если есть).\n"
        + json.dumps(postgres_profile_payload, ensure_ascii=False, default=str)
    )
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://local.pg-query-analyzer",
        "X-Title": "PostgreSQL Query Plan Analyzer",
    }
    req = request.Request(url, data=body, headers=headers, method="POST")
    ssl_context = _build_ssl_context()
    try:
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_context) as response:
            response_data = response.read().decode("utf-8", errors="replace")
        parsed = json.loads(response_data)
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        reason = _extract_error_message(raw) or exc.reason or "HTTP ошибка"
        raise RuntimeError(f"Ошибка OpenRouter ({exc.code}): {reason}") from exc
    except error.URLError as exc:
        raise RuntimeError(
            _urlopen_network_message(exc, "Сетевая ошибка при подключении к OpenRouter")
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(_ssl_error_hint(exc)) from exc
    except TimeoutError as exc:
        raise RuntimeError("Таймаут запроса в OpenRouter") from exc

    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenRouter вернул пустой ответ (choices отсутствует).")
    message = (choices[0].get("message") or {}).get("content") or ""
    text = str(message).strip()
    if not text:
        raise RuntimeError("OpenRouter не вернул персональные рекомендации.")
    return {"raw_text": text, "structured": _parse_postgres_tuning_structured_response(text)}


def _parse_postgres_tuning_structured_response(text):
    if not text:
        return None
    stripped = text.strip()
    candidate = stripped
    if "```" in stripped:
        chunks = stripped.split("```")
        for chunk in chunks:
            cleaned = chunk.strip()
            if cleaned.startswith("{") and cleaned.endswith("}"):
                candidate = cleaned
                break
            if cleaned.startswith("json"):
                maybe = cleaned[4:].strip()
                if maybe.startswith("{") and maybe.endswith("}"):
                    candidate = maybe
                    break
    if not (candidate.startswith("{") and candidate.endswith("}")):
        return None
    try:
        parsed = json.loads(candidate)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if not isinstance(parsed.get("summary"), str):
        return None
    if not isinstance(parsed.get("recommendations"), list):
        return None
    if not isinstance(parsed.get("risks"), list):
        return None
    if not isinstance(parsed.get("read_only_checks"), list):
        return None
    if not isinstance(parsed.get("confidence"), (int, float)):
        return None
    return parsed


def _urlopen_network_message(exc: error.URLError, detail_label: str) -> str:
    """urllib wraps SSL errors inside URLError; normalize to a clear TLS hint."""
    r = exc.reason
    if isinstance(r, ssl.SSLError):
        return _ssl_error_hint(r)
    return f"{detail_label}: {r}"


def _build_ssl_context():
    """TLS context for OpenRouter. Uses certifi CA bundle (fixes macOS / stripped Python builds).

    ``PSQLQA_OPENROUTER_SSL_INSECURE=1`` disables verification (last resort; unsafe).
    """
    insecure = os.environ.get("PSQLQA_OPENROUTER_SSL_INSECURE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if certifi is not None:
        try:
            bundle = certifi.where()
            if bundle and os.path.isfile(bundle):
                return ssl.create_default_context(cafile=bundle)
        except Exception:
            pass
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            bundle = certifi.where()
            if bundle and os.path.isfile(bundle):
                ctx.load_verify_locations(cafile=bundle)
                return ctx
        except Exception:
            pass

    return ssl.create_default_context()


def _ssl_error_hint(exc: Exception) -> str:
    return (
        "TLS ошибка при подключении к OpenRouter: "
        f"{exc}. Убедитесь, что установлен пакет certifi: "
        "`pip install certifi` в окружении приложения и перезапуск. "
        "Если ошибка сохраняется, обновите корневые сертификаты ОС. "
        "Крайний вариант (небезопасно): переменная окружения PSQLQA_OPENROUTER_SSL_INSECURE=1."
    )
