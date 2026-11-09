# src/uniconn/parsing/engines/json_engine.py
"""Встроенный движок парсинга JSON и JSON Lines (Zero-Dependency)."""

from __future__ import annotations

import json
from typing import Any

from ...exceptions import ParsingError


class NativeJsonEngine:
    """Движок разбора JSON и JSON Lines (NDJSON) без сторонних зависимостей."""

    name: str = "json"
    _SUPPORTED_SPECS: frozenset[str] = frozenset({"json", "jsonl", "json_lines", "ndjson"})

    def can_parse(self, spec: str) -> bool:
        """Проверить, относится ли спецификация к формату JSON или JSON Lines."""
        return spec.lower() in self._SUPPORTED_SPECS

    def parse(self, text: str, spec: str = "json", **kwargs: Any) -> Any:
        """Распарсить текст в формате JSON или JSON Lines."""
        norm_spec = spec.lower()
        stripped = text.strip()
        if not stripped:
            if norm_spec in ("jsonl", "json_lines", "ndjson"):
                return []
            raise ParsingError("Cannot parse empty stdout as JSON.")

        if norm_spec in ("jsonl", "json_lines", "ndjson"):
            return self._parse_jsonl(stripped)

        try:
            return json.loads(stripped)
        except json.JSONDecodeError as first_err:
            # Попытка извлечь валидный JSON-блок, если перед ним были диагностические строки логов
            extracted = self._extract_embedded_json(stripped)
            if extracted is not None:
                return extracted
            raise ParsingError(f"Failed to parse output as JSON: {first_err}") from first_err

    @staticmethod
    def _parse_jsonl(stripped: str) -> list[Any]:
        """Распарсить поток JSON Lines (по одному JSON-объекту на строку)."""
        items: list[Any] = []
        for line_no, raw_line in enumerate(stripped.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as err:
                raise ParsingError(
                    f"Failed to parse JSONL at line {line_no}: {err}"
                ) from err
        return items

    @staticmethod
    def _extract_embedded_json(text: str) -> Any | None:
        """Попытаться найти JSON-объект или массив в выводе с префиксными или суффиксными логами."""
        decoder = json.JSONDecoder()
        candidates: list[tuple[int, Any]] = []
        for idx, ch in enumerate(text):
            if ch in ("{", "["):
                try:
                    obj, end_idx = decoder.raw_decode(text, idx)
                    if not text[end_idx:].strip():
                        return obj
                    span_len = end_idx - idx
                    candidates.append((span_len, obj))
                except json.JSONDecodeError:
                    continue
        if candidates:
            # Возвращаем кандидата с наибольшей длиной распарсенного фрагмента
            candidates.sort(key=lambda item: item[0], reverse=True)
            return candidates[0][1]
        return None


__all__ = ["NativeJsonEngine"]
