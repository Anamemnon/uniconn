Transports & Secret Resolution
==============================

Secret Resolution (``env://`` & ``file://``)
--------------------------------------------

В полях ``password``, ``key_file``, ``passphrase``, ``sudo_password`` и в файлах инвентарей
поддерживается динамическая подстановка секретов::

    conn = Connection.from_uri(
        "ssh://admin:env://SSH_PASS?default=fallback@node-01"
        "?key_file=file:///run/secrets/id_ed25519"
    )

SSH
---

URI формат::

    ssh://[user[:password]@]host[:port][?option=value]

Примеры::

    # Базовая аутентификация или из переменной окружения
    conn = Connection.from_uri("ssh://user:env://SSH_PASS@host")

    # По ключу с учётом ~/.ssh/config и Jump-хостов
    conn = Connection.from_uri("ssh://user@host?key_file=/path/to/key&ssh_config=true&proxy=jump1,jump2")

    # С лимитом частоты и CircuitBreaker
    conn = Connection.from_uri("ssh://user@host?rate_limit=20&circuit_breaker_threshold=5")

Docker & Podman
---------------

URI формат::

    docker://[user@]container_name_or_id[?workdir=/app&shell=/bin/sh&context=...]
    podman://[user@]container_name_or_id[?workdir=/app&shell=/bin/sh]

Примеры::

    conn = Connection.from_uri("docker://root@redis-cache?workdir=/data")
    conn = Connection.from_uri("podman://web-app?workdir=/srv/www")

Kubernetes (``kubectl``)
------------------------

URI формат::

    kubectl://[namespace/]pod_name[?container=app&context=prod&kubeconfig=/path/config&workdir=/app]

Примеры::

    conn = Connection.from_uri("kubectl://production/api-pod-0?container=api&workdir=/app")

Redfish & IPMI (BMC)
--------------------

URI формат::

    redfish://[user[:password]@]host[:443][?verify_ssl=false&system_id=1&chassis_id=1&manager_id=1]
    ipmi://[user[:password]@]host[:623]

Примеры::

    bmc_rf = Connection.from_uri("redfish://admin:env://BMC_PASS@bmc.local?verify_ssl=false")
    bmc_ipmi = Connection.from_uri("ipmi://admin:env://BMC_PASS@bmc.local:623")

Основные команды BMC: ``power on``, ``power off``, ``power cycle``, ``power status``, ``sensors``, ``system info``, ``boot device``.

Serial / UART
-------------

URI формат::

    serial://[device][?option=value]
    uart://[device[:baudrate]][?option=value]

Примеры::

    conn = Connection.from_uri("uart:///dev/ttyUSB0:115200?parity=N&stopbits=1")
    conn = Connection.from_uri("uart://COM3:115200?parity=even&stopbits=1.5")
    conn = Connection.from_uri("uart://?vid=10c4&pid=ea60")

Telnet
------

URI формат::

    telnet://[user[:password]@]host[:port][?term_type=vt100&timeout=30]

Replay & Contract Testing
-------------------------

URI формат::

    replay://host[?cassette=path/to/cassette.yaml&mode=none&normalize_temp=true]

Примеры::

    conn = Connection.from_uri("replay://node-01?cassette=tests/cassettes/node.yaml&mode=none")

Local
-----

URI формат::

    local://[?timeout=30&rate_limit=50]

Примеры::

    conn = Connection.local(timeout=30.0)
    conn = Connection.from_uri("local://?timeout=60")
