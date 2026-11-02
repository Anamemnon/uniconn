Provisioning, Facts & Stress Diagnostics
========================================

Идемпотентное управление состоянием (``conn.state``), сбор системных фактов (``gather_facts``),
анализ расхождений между хостами (``diff_facts``) и отказоустойчивые диагностические сессии
для нагрузочного тестирования (``conn.diagnostic_session``).

.. literalinclude:: ../../examples/provisioning_and_facts.py
   :language: python
   :linenos:

Stress Testing & Crash-Safe Diagnostics (NVMe / RAM)
----------------------------------------------------

Декларативный YAML-профиль сбора статических и потоковых логов:

.. literalinclude:: ../../examples/stress_test_diagnostics.yaml
   :language: yaml
   :linenos:

Скрипт запуска нагрузочного теста со сбором логов (из YAML и Python ``dict``):

.. literalinclude:: ../../examples/stress_test_diagnostics.py
   :language: python
   :linenos:

