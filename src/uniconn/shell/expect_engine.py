# src/uniconn/shell/expect_engine.py
"""Декларативный конечный автомат сопоставления регулярных выражений для интерактивных CLI."""

from __future__ import annotations

import asyncio
import builtins
import re
from collections.abc import Awaitable, Callable, Mapping

from pydantic import SecretStr

from ..exceptions import ConnectionError


class ExpectStateMachine:
    """Выполняет интерактивный диалог по правилам ``{regex: response}`` до ``final_prompt`` или EOF."""

    def __init__(
        self,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        allow_eof: bool = True,
    ) -> None:
        """Инициализировать конечный автомат скомпилированными регулярными выражениями."""
        self.compiled_patterns: list[tuple[re.Pattern[str], str]] = []
        for pat_str, raw_resp in (patterns or {}).items():
            secret_fn = getattr(raw_resp, "get_secret_value", None)
            resp_text = str(secret_fn()) if callable(secret_fn) else str(raw_resp)
            self.compiled_patterns.append((re.compile(pat_str, re.MULTILINE), resp_text))

        self.final_re = (
            re.compile(final_prompt, re.MULTILINE) if final_prompt else None
        )
        self.allow_eof = allow_eof

    async def run_dialog(
        self,
        *,
        initial_buffer: str,
        send_fn: Callable[[str], Awaitable[None]],
        read_chunk_fn: Callable[[], Awaitable[str]],
        is_alive_fn: Callable[[], bool],
        mark_closed_fn: Callable[[], None],
        effective_timeout: float,
        cmd_for_error: str,
        host: str | None,
    ) -> tuple[str, str]:
        """Прогнать цикл чтения и сопоставления паттернов.

        Returns:
            Кортеж ``(raw_output, remaining_buffer)``.

        """
        accumulated = initial_buffer
        cursor = 0
        matched_indices: set[int] = set()

        while True:
            candidates: list[tuple[bool, int, int, int, re.Match[str], str]] = []
            for idx, (pat_re, resp_text) in enumerate(self.compiled_patterns):
                m = pat_re.search(accumulated, cursor)
                if m is not None:
                    candidates.append(
                        (
                            idx in matched_indices,
                            m.start(),
                            -len(m.group(0)),
                            idx,
                            m,
                            resp_text,
                        )
                    )
            if candidates:
                candidates.sort(key=lambda item: item[:4])
                _, _, _, win_idx, win_m, win_resp = candidates[0]
                if win_idx not in matched_indices or self.final_re is not None:
                    cursor = win_m.end()
                    matched_indices.add(win_idx)
                    if win_resp:
                        await send_fn(win_resp)
                    continue

            if self.final_re is not None:
                m_final = self.final_re.search(accumulated, cursor)
                if m_final is not None:
                    out_end = m_final.end()
                    return accumulated[:out_end], accumulated[out_end:]

            all_patterns_done = bool(self.compiled_patterns) and len(
                matched_indices
            ) == len(self.compiled_patterns)

            if not is_alive_fn():
                mark_closed_fn()
                if self.allow_eof or (
                    self.final_re is None
                    and (all_patterns_done or not self.compiled_patterns)
                ):
                    return accumulated, ""
                raise ConnectionError(
                    "Shell process terminated during expect()",
                    command=cmd_for_error,
                    host=host,
                )

            if self.final_re is None and all_patterns_done:
                try:
                    chunk = await asyncio.wait_for(
                        read_chunk_fn(),
                        timeout=min(0.15, effective_timeout),
                    )
                except builtins.TimeoutError:
                    return accumulated, ""
            else:
                chunk = await read_chunk_fn()

            if chunk == "":
                mark_closed_fn()
                if (
                    self.allow_eof
                    or (
                        self.final_re is None
                        and (all_patterns_done or not self.compiled_patterns)
                    )
                    or (
                        self.final_re is not None
                        and self.final_re.search(accumulated, cursor) is not None
                    )
                ):
                    return accumulated, ""
                raise ConnectionError(
                    "Shell process closed stdout unexpectedly (EOF)",
                    command=cmd_for_error,
                    host=host,
                )
            accumulated += chunk
