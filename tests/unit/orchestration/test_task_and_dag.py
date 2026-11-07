# tests/unit/orchestration/test_task_and_dag.py
"""Unit-тесты декоратора @task, построения графа Flow, валидации циклов и FlowContext."""

from __future__ import annotations

import pytest

from uniconn import (
    ConfigurationError,
    Connection,
    CyclicDependencyError,
    Flow,
    FlowContext,
    Task,
    task,
)


def test_task_decorator_preserves_metadata_and_supports_bare_and_parametrized() -> None:
    """Декоратор @task работает со скобками и без, сохраняет __doc__ и __name__, объединяет pre и depends_on."""

    @task
    async def step_a(conn: Connection) -> str:
        """Docstring for step_a."""
        return "a"

    @task(name="custom_b", pre=[step_a], retries=2, tags=["db", "init"], always_run=True)
    async def step_b(conn: Connection) -> str:
        """Docstring for step_b."""
        return "b"

    assert isinstance(step_a, Task)
    assert step_a.name == "step_a"
    assert step_a.__doc__ == "Docstring for step_a."

    assert isinstance(step_b, Task)
    assert step_b.name == "custom_b"
    assert step_b.__doc__ == "Docstring for step_b."
    assert step_b.depends_on == (step_a,)
    assert step_b.tags == ("db", "init")
    assert step_b.always_run is True
    assert step_b.options.retries == 2


def test_task_invalid_options_raise_configuration_error() -> None:
    """Некорректные параметры retries, concurrency или не-callable зависимости вызывают ConfigurationError."""
    with pytest.raises(ConfigurationError):
        task(retries=-1)(lambda: None)

    with pytest.raises(ConfigurationError):
        task(concurrency=0)(lambda: None)

    with pytest.raises(ConfigurationError):
        task(depends_on=["not_a_task"])(lambda: None)  # type: ignore[list-item]


def test_flow_transitive_registration_and_post_edge_inversion() -> None:
    """Flow транзитивно регистрирует depends_on и инвертирует рёбра post=[cleanup]."""

    @task
    def check_disk() -> None:
        pass

    @task(always_run=True)
    def cleanup() -> None:
        pass

    @task(pre=[check_disk], post=[cleanup])
    def deploy() -> None:
        pass

    # Передаём только deploy — check_disk и cleanup должны подтянуться автоматически
    flow = Flow(name="deploy_flow", tasks=[deploy])
    assert set(flow.tasks.keys()) == {"check_disk", "deploy", "cleanup"}
    assert flow.dag["deploy"] == {"check_disk"}
    assert flow.dag["cleanup"] == {"deploy"}

    ordered_names = [t.name for t in flow.tasks_in_order()]
    assert ordered_names == ["check_disk", "deploy", "cleanup"]

    layers = [[t.name for t in layer] for layer in flow.get_layers()]
    assert layers == [["check_disk"], ["deploy"], ["cleanup"]]


def test_flow_diamond_dag_layers() -> None:
    """Ромбовидный граф (A -> B, C -> D) разбивается на 3 параллельных слоя."""

    @task
    def init() -> None:
        pass

    @task(depends_on=[init])
    def upload_code() -> None:
        pass

    @task(depends_on=[init])
    def render_config() -> None:
        pass

    @task(depends_on=[upload_code, render_config])
    def restart_service() -> None:
        pass

    flow = Flow("diamond", tasks=[restart_service])
    layers = [sorted(t.name for t in layer) for layer in flow.get_layers()]
    assert layers == [
        ["init"],
        ["render_config", "upload_code"],
        ["restart_service"],
    ]


def test_flow_cycle_detection_raises_cyclic_dependency_error() -> None:
    """Цикл в графе выбрасывает CyclicDependencyError (наследник ConfigurationError) с путём цикла."""

    @task
    def task_a() -> None:
        pass

    @task(depends_on=[task_a])
    def task_b() -> None:
        pass

    @task(depends_on=[task_b], post=[task_a])
    def task_c() -> None:
        pass

    with pytest.raises(CyclicDependencyError) as exc_info:
        Flow("cyclic_flow", tasks=[task_c])

    err = exc_info.value
    assert isinstance(err, ConfigurationError)
    assert len(err.cycle) >= 3
    assert "->" in str(err)


def test_flow_duplicate_task_name_with_different_callables_raises_error() -> None:
    """Две разные функции с одинаковым именем задачи вызывают ConfigurationError."""

    @task(name="dup")
    def fn1() -> None:
        pass

    @task(name="dup")
    def fn2() -> None:
        pass

    with pytest.raises(ConfigurationError, match="Duplicate task name"):
        Flow("dup_flow", tasks=[fn1, fn2])


def test_flow_context_shared_and_host_vars_normalization() -> None:
    """FlowContext корректно сопоставляет URI пула, короткое имя хоста и объект Connection."""
    ctx = FlowContext("ctx_test", initial_vars={"env": "staging"})
    assert ctx.get("env") == "staging"
    ctx.set("version", "1.2.3")
    ctx.update({"region": "eu"}, build=42)
    assert ctx.vars == {"env": "staging", "version": "1.2.3", "region": "eu", "build": 42}

    conn = Connection.from_uri("ssh://deploy@web-01.prod:2222")
    ctx.register_host_alias("ssh://deploy@web-01.prod:2222", conn)

    # Записываем через объект Connection, читаем по URI и по короткому имени хоста
    ctx.host_set(conn, "os", "Ubuntu")
    assert ctx.host_get("ssh://deploy@web-01.prod:2222", "os") == "Ubuntu"
    assert ctx.host_get("web-01.prod", "os") == "Ubuntu"
    assert ctx.host_get(conn, "os") == "Ubuntu"
    assert ctx.host_vars("web-01.prod") == {"os": "Ubuntu"}


def test_flow_to_rich_tree_renders_cleanly() -> None:
    """Метод flow.to_rich_tree() строит дерево слоёв и флагов без ошибок."""

    @task(tags=["check"])
    def step1() -> None:
        pass

    @task(depends_on=[step1], retries=2, ignore_errors=True, always_run=True)
    def step2() -> None:
        pass

    flow = Flow("tree_test", tasks=[step2])
    tree = flow.to_rich_tree()
    assert "tree_test" in str(tree.label)
    assert len(tree.children) == 2
