Transports
==========

SSH
---

URI формат::

    ssh://[user[:password]@]host[:port][?option=value]

Примеры::

    # Базовая аутентификация
    conn = Connection.from_uri("ssh://user:pass@host")

    # По ключу
    conn = Connection.from_uri("ssh://user@host?key_file=/path/to/key")

    # С проверкой known_hosts
    conn = Connection.from_uri("ssh://user@host?known_hosts=strict")

    # Через jump-хост
    conn = Connection.from_uri("ssh://user@host?proxy=jump1.example.com")

Опции:

============  =====================================
Параметр      Описание
============  =====================================
known_hosts   strict / default / путь / no
proxy         comma-separated список jump хостов
timeout       Таймаут подключения
============  =====================================

Telnet
------

URI формат::

    telnet://[user[:password]@]host[:port][?option=value]

Примеры::

    conn = Connection.from_uri("telnet://user:pass@router:23")
    conn = Connection.from_uri("telnet://host?timeout=30&term_type=vt100")

Serial
------

URI формат::

    serial://[device][?option=value]

Примеры::

    # Linux
    conn = Connection.from_uri("serial:///dev/ttyUSB0?baudrate=9600")

    # Windows
    conn = Connection.from_uri("serial://COM3?baudrate=115200")

    # С полными настройками
    conn = Connection.from_uri("serial:///dev/ttyS0?baudrate=115200&parity=N&stopbits=1")

Опции:

============  =============================
Параметр      Описание
============  =============================
baudrate      Скорость (по умолч. 9600)
parity        N / E / O
stopbits      1 / 2
xonxoff       Программный flow control
rtscts        Аппаратный flow control
============  =============================

Local
-----

URI формат::

    local://[?option=value]

Примеры::

    conn = Connection.from_uri("local://")
    conn = Connection.from_uri("local://?timeout=60")

IPMI (BMC)
----------

URI формат::

    ipmi://[user[:password]@]host[:port]

Примеры::

    conn = Connection.from_uri("ipmi://admin:password@bmc.local")
    conn = Connection.from_uri("ipmi://admin:password@bmc.local:623")

Доступные команды:

==================  ===========================
Команда             Описание
==================  ===========================
power on            Включить сервер
power off           Выключить сервер
power cycle         Перезагрузить
power status        Статус питания
sensors             Данные сенсоров
boot device         Boot устройство
==================  ===========================

Redfish (BMC)
-------------

URI формат::

    redfish://[user[:password]@]host[:port][/path][?option=value]

Примеры::

    conn = Connection.from_uri("redfish://admin:pass@bmc.local")
    conn = Connection.from_uri("redfish://admin:pass@bmc.local?verify_ssl=false")

Доступные команды:

==================  ===========================
Команда             Описание
==================  ===========================
power on/off        Управление питанием
power cycle         Перезагрузка
boot device         Boot устройство
sensors             Сенсоры
info                Информация о системе
get /path           Произвольный GET запрос
post /path data     Произвольный POST запрос
==================  ===========================
