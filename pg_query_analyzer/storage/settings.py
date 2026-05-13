"""Analyzer settings persistence."""

from copy import deepcopy
import json
import logging
import os

from pg_query_analyzer.storage.json_io import atomic_write_json

ANALYZER_SETTINGS_FILE = "analyzer_settings.json"


def get_analyzer_settings_path(settings_dir):
    return os.path.join(settings_dir, ANALYZER_SETTINGS_FILE)


def merge_settings(default_settings, loaded_settings):
    """Deep-merge loaded settings into defaults without mutating the input defaults."""
    merged = deepcopy(default_settings)

    def update_settings(default, loaded):
        for key in default:
            if key in loaded:
                if isinstance(default[key], dict) and isinstance(loaded[key], dict):
                    update_settings(default[key], loaded[key])
                else:
                    default[key] = loaded[key]

    if isinstance(loaded_settings, dict):
        update_settings(merged, loaded_settings)

    return merged


def save_analyzer_settings(settings_dir, settings):
    os.makedirs(settings_dir, exist_ok=True)
    settings_file = get_analyzer_settings_path(settings_dir)

    atomic_write_json(settings_file, settings, indent=2, ensure_ascii=False)

    logging.info(f"Настройки анализатора сохранены в {settings_file}")


def load_analyzer_settings(settings_dir, default_settings):
    settings_file = get_analyzer_settings_path(settings_dir)

    try:
        if os.path.exists(settings_file):
            with open(settings_file, "r", encoding="utf-8") as f:
                loaded_settings = json.load(f)

            settings = merge_settings(default_settings, loaded_settings)
            logging.info(f"Настройки анализатора загружены из {settings_file}")
            return settings

        settings = deepcopy(default_settings)
        save_analyzer_settings(settings_dir, settings)
        logging.info(f"Создан файл настроек по умолчанию: {settings_file}")
        return settings

    except Exception as e:
        logging.error(f"Ошибка загрузки настроек анализатора: {e}")
        settings = deepcopy(default_settings)
        save_analyzer_settings(settings_dir, settings)
        return settings
