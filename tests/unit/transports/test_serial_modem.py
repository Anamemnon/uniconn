# tests/unit/transports/test_serial_modem.py
"""Комплексные unit-тесты для протоколов передачи файлов по Serial/UART (XMODEM / YMODEM / ZMODEM)."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import (
    AsyncXmodemReceiver,
    AsyncXmodemSender,
    AsyncYmodemReceiver,
    AsyncYmodemSender,
    CapabilityNotSupportedError,
    Connection,
    ConnectionConfig,
    ConnectionPool,
    ModemCancelledError,
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
    ModemProtocolError,
    ModemTransferError,
    SerialTransport,
    SyncConnection,
    ZmodemSubprocessAdapter,
    compute_checksum8,
    compute_crc16,
)
from uniconn.transports.serial_protocols import (
    ACK,
    CAN,
    CRC_CHR,
    EOT,
    NAK,
    PACKET_SIZE_1K,
    PACKET_SIZE_128,
    SOH,
    STX,
    SUB,
    build_xmodem_packet,
    build_ymodem_header_packet,
    parse_ymodem_header_payload,
)


class MockAsyncSerialPair:
    """Двунаправленная пара потоков StreamReader/StreamWriter в памяти для тестирования модемных протоколов."""

    def __init__(self) -> None:
        self.a_to_b = asyncio.StreamReader()
        self.b_to_a = asyncio.StreamReader()
        self.writer_a = self._make_writer(self.a_to_b)
        self.writer_b = self._make_writer(self.b_to_a)
        self.a_written: list[bytes] = []
        self.b_written: list[bytes] = []

    def _make_writer(self, target_reader: asyncio.StreamReader) -> MagicMock:
        writer = MagicMock()

        def _write(data: bytes) -> None:
            raw = bytes(data)
            if target_reader is self.a_to_b:
                self.a_written.append(raw)
            else:
                self.b_written.append(raw)
            target_reader.feed_data(raw)

        writer.write = MagicMock(side_effect=_write)
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        return writer


# ─── T01: CRC-16-CCITT и Checksum8 ─────────────────────────────────────────


def test_crc16_standard_vectors() -> None:
    """T01: Проверка тестового вектора b'123456789' -> 0x31C3 и краевых случаев."""
    assert compute_crc16(b"123456789") == 0x31C3
    assert compute_crc16(b"") == 0x0000
    assert compute_crc16(b"\x00" * 128) == 0x0000
    assert compute_crc16(bytearray(b"123456789")) == 0x31C3
    assert compute_crc16(memoryview(b"123456789")) == 0x31C3
    assert compute_checksum8(b"\x01\x02\x03") == 6
    assert compute_checksum8(b"\xff\x02") == 1


# ─── T02-T08: XMODEM Sender & Receiver ─────────────────────────────────────


@pytest.mark.asyncio
async def test_xmodem_send_checksum_success() -> None:
    """T02: Отправка 256 байт в режиме 8-битной контрольной суммы (ответ NAK на старте)."""
    pair = MockAsyncSerialPair()
    payload = bytes(range(256))

    # Получатель шлёт NAK для запроса режима checksum, затем ACK на пакет 1, ACK на пакет 2,
    # NAK на первый EOT и ACK на второй EOT
    pair.b_to_a.feed_data(NAK + ACK + ACK + NAK + ACK)

    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    progress_calls: list[tuple[int, int]] = []
    sent = await sender.send(
        io.BytesIO(payload),
        total_size=len(payload),
        mode="checksum",
        progress_callback=lambda s, t: progress_calls.append((s, t)),
    )

    assert sent == 256
    assert progress_calls == [(128, 256), (256, 256)]
    # Пакет 1 (132 байта: SOH + seq + ~seq + 128B + 1B checksum), Пакет 2, EOT, EOT
    assert len(pair.a_written) == 4
    assert pair.a_written[0][0:1] == SOH
    assert len(pair.a_written[0]) == 3 + PACKET_SIZE_128 + 1
    assert pair.a_written[2] == EOT
    assert pair.a_written[3] == EOT


@pytest.mark.asyncio
async def test_xmodem_send_crc_success() -> None:
    """T03: Отправка 300 байт в режиме CRC-16 (ответ 'C' на старте, 3 пакета по 128B с padding 0x1A)."""
    pair = MockAsyncSerialPair()
    payload = b"A" * 300

    pair.b_to_a.feed_data(CRC_CHR + ACK + ACK + ACK + ACK)

    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    sent = await sender.send(io.BytesIO(payload), total_size=len(payload), mode="crc")

    assert sent == 300
    assert len(pair.a_written) == 4  # 3 пакета SOH + 1 EOT
    last_pkt = pair.a_written[2]
    assert last_pkt[0:1] == SOH
    assert len(last_pkt) == 3 + PACKET_SIZE_128 + 2
    # 300 - 256 = 44 байта 'A' и 84 байта SUB (0x1A)
    data_part = last_pkt[3 : 3 + PACKET_SIZE_128]
    assert data_part == (b"A" * 44) + (SUB * 84)


@pytest.mark.asyncio
async def test_xmodem_send_1k_success() -> None:
    """T04: Отправка файла > 2 КБ в режиме 1k (блоки STX по 1024 байта)."""
    pair = MockAsyncSerialPair()
    payload = b"X" * 2048

    pair.b_to_a.feed_data(CRC_CHR + ACK + ACK + ACK)

    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    sent = await sender.send(io.BytesIO(payload), total_size=len(payload), mode="1k")

    assert sent == 2048
    assert len(pair.a_written) == 3  # 2 пакета STX + 1 EOT
    assert pair.a_written[0][0:1] == STX
    assert len(pair.a_written[0]) == 3 + PACKET_SIZE_1K + 2


@pytest.mark.asyncio
async def test_xmodem_retry_on_nak() -> None:
    """T05: Имитация повреждения пакета №2 (получатель шлёт NAK), повтор пакета и успешное завершение."""
    pair = MockAsyncSerialPair()
    payload = b"B" * 256

    # 'C', ACK для пакета 1, NAK для пакета 2, ACK для повтора пакета 2, ACK для EOT
    pair.b_to_a.feed_data(CRC_CHR + ACK + NAK + ACK + ACK)

    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    sent = await sender.send(io.BytesIO(payload), total_size=len(payload), mode="crc")

    assert sent == 256
    assert len(pair.a_written) == 4  # pkt1, pkt2, pkt2(retry), EOT
    assert pair.a_written[1] == pair.a_written[2]


@pytest.mark.asyncio
async def test_xmodem_max_retries_exceeded() -> None:
    """T06: Имитация 5 подряд идущих NAK на одном пакете -> выброс ModemMaxRetriesError."""
    pair = MockAsyncSerialPair()
    payload = b"C" * 128

    pair.b_to_a.feed_data(CRC_CHR + (NAK * 5))

    sender = AsyncXmodemSender(
        pair.b_to_a,
        pair.writer_a,
        max_retries=5,
        packet_timeout=0.5,
        handshake_timeout=1.0,
    )
    with pytest.raises(ModemMaxRetriesError, match="Max retries"):
        await sender.send(io.BytesIO(payload), mode="crc")


@pytest.mark.asyncio
async def test_xmodem_receiver_cancelled() -> None:
    """T07: Имитация получения CAN CAN от получателя -> выброс ModemCancelledError."""
    pair = MockAsyncSerialPair()
    pair.b_to_a.feed_data(CRC_CHR + CAN + CAN)

    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=0.5, handshake_timeout=1.0)
    with pytest.raises(ModemCancelledError, match="cancelled"):
        await sender.send(io.BytesIO(b"hello"), mode="crc")


@pytest.mark.asyncio
async def test_xmodem_handshake_timeout() -> None:
    """T08: Отсутствие стартового ответа в течение handshake_timeout -> выброс ModemHandshakeTimeoutError."""
    pair = MockAsyncSerialPair()
    sender = AsyncXmodemSender(
        pair.b_to_a,
        pair.writer_a,
        packet_timeout=0.05,
        handshake_timeout=0.1,
    )
    with pytest.raises(ModemHandshakeTimeoutError, match="timed out"):
        await sender.send(io.BytesIO(b"hello"), mode="crc")


@pytest.mark.asyncio
async def test_xmodem_full_duplex_sender_and_receiver_loopback() -> None:
    """Полный цикл передачи между AsyncXmodemSender и AsyncXmodemReceiver в памяти."""
    pair = MockAsyncSerialPair()
    original_data = b"Hello XMODEM-1K world! " * 60  # 1380 байт

    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    receiver = AsyncXmodemReceiver(pair.a_to_b, pair.writer_b, packet_timeout=1.0)

    out_buf = io.BytesIO()
    send_task = asyncio.create_task(sender.send(io.BytesIO(original_data), total_size=len(original_data), mode="1k"))
    recv_task = asyncio.create_task(receiver.receive(out_buf, mode="1k", strip_padding=True))

    sent_bytes, recv_bytes = await asyncio.gather(send_task, recv_task)
    assert sent_bytes == len(original_data)
    assert recv_bytes == len(original_data)
    assert out_buf.getvalue() == original_data


@pytest.mark.asyncio
async def test_xmodem_receiver_handles_duplicate_packet_and_corrupt_crc() -> None:
    """AsyncXmodemReceiver игнорирует дубликат предыдущего пакета и запрашивает NAK при битом CRC."""
    pair = MockAsyncSerialPair()
    pkt1 = build_xmodem_packet(1, b"block_one", block_size=128, use_crc=True)
    # Дубликат пакета 1
    pkt1_dup = pkt1
    # Битый пакет 2 (инвертируем последний байт CRC)
    pkt2_good = build_xmodem_packet(2, b"block_two", block_size=128, use_crc=True)
    pkt2_corrupt = pkt2_good[:-1] + bytes((pkt2_good[-1] ^ 0xFF,))

    pair.a_to_b.feed_data(pkt1 + pkt1_dup + pkt2_corrupt + pkt2_good + EOT)

    receiver = AsyncXmodemReceiver(pair.a_to_b, pair.writer_b, packet_timeout=1.0)
    out_buf = io.BytesIO()
    written = await receiver.receive(out_buf, mode="crc", strip_padding=True)

    assert out_buf.getvalue() == (b"block_one" + SUB * (128 - 9)) + b"block_two"
    assert written == 128 + 9
    # Ответы приёмника: 'C' (старт), ACK (pkt1), ACK (pkt1_dup), NAK (pkt2_corrupt), ACK (pkt2_good), ACK (EOT)
    assert pair.b_written == [CRC_CHR, ACK, ACK, NAK, ACK, ACK]


# ─── T09-T11: YMODEM (Packet 0, Sender & Receiver) ─────────────────────────


def test_ymodem_packet_zero_format() -> None:
    """T09: Проверка сериализации и парсинга имени, размера и прав в Пакет 0 YMODEM."""
    pkt0 = build_ymodem_header_packet("firmware.bin", 1048576, mtime=1700000000, mode=0o644)
    assert pkt0[0:1] == SOH
    assert pkt0[1] == 0x00
    assert pkt0[2] == 0xFF
    assert len(pkt0) == 3 + PACKET_SIZE_128 + 2

    payload = pkt0[3 : 3 + PACKET_SIZE_128]
    fname, fsize, mtime, fmode = parse_ymodem_header_payload(payload)
    assert fname == "firmware.bin"
    assert fsize == 1048576
    assert mtime == 1700000000
    assert fmode == 0o644

    # End-of-Batch Null Packet 0
    null_pkt = build_ymodem_header_packet("")
    null_payload = null_pkt[3 : 3 + PACKET_SIZE_128]
    assert null_payload == b"\x00" * PACKET_SIZE_128
    assert parse_ymodem_header_payload(null_payload) == ("", 0, None, None)


@pytest.mark.asyncio
async def test_ymodem_send_file_and_receive_exact_size(tmp_path: Path) -> None:
    """T10 & T11: Полный цикл YMODEM между Sender и Receiver с точной обрезкой хвостовых нулей."""
    src_file = tmp_path / "u-boot.bin"
    # Размер 1100 байт: 1 блок 1024B (STX) + 1 блок 128B (SOH, где 76 байт данных и 52 байта 0x00)
    # Причём сам файл заканчивается байтом SUB (0x1A) и нулём (0x00), чтобы проверить точное сохранение!
    raw_content = (b"\xde\xad\xbe\xef" * 274) + b"\x1a\x00\x55\xaa"
    assert len(raw_content) == 1100
    src_file.write_bytes(raw_content)

    dest_dir = tmp_path / "received"
    pair = MockAsyncSerialPair()

    sender = AsyncYmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    receiver = AsyncYmodemReceiver(pair.a_to_b, pair.writer_b, packet_timeout=1.0)

    send_progress: list[tuple[int, int]] = []
    recv_progress: list[tuple[int, int, str]] = []

    send_task = asyncio.create_task(
        sender.send_file(src_file, progress_callback=lambda s, t: send_progress.append((s, t)))
    )
    recv_task = asyncio.create_task(
        receiver.receive_batch(dest_dir, progress_callback=lambda s, t, n: recv_progress.append((s, t, n)))
    )

    sent_total, saved_paths = await asyncio.gather(send_task, recv_task)
    assert sent_total == 1100
    assert len(saved_paths) == 1
    assert saved_paths[0].name == "u-boot.bin"
    assert saved_paths[0].read_bytes() == raw_content
    assert send_progress[-1] == (1100, 1100)
    assert recv_progress[-1] == (1100, 1100, "u-boot.bin")


@pytest.mark.asyncio
async def test_ymodem_batch_multiple_files(tmp_path: Path) -> None:
    """Пакетная передача нескольких файлов в рамках одной YMODEM-Batch сессии."""
    f1 = tmp_path / "kernel.img"
    f2 = tmp_path / "dtb.dtb"
    f1.write_bytes(b"KERNEL_DATA_" * 100)
    f2.write_bytes(b"DTB_TREE_BLOB")

    dest_dir = tmp_path / "batch_out"
    pair = MockAsyncSerialPair()

    sender = AsyncYmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)
    receiver = AsyncYmodemReceiver(pair.a_to_b, pair.writer_b, packet_timeout=1.0)

    total_sent, saved = await asyncio.gather(
        sender.send_batch([f1, f2]),
        receiver.receive_batch(dest_dir),
    )

    assert total_sent == f1.stat().st_size + f2.stat().st_size
    assert [p.name for p in saved] == ["kernel.img", "dtb.dtb"]
    assert (dest_dir / "kernel.img").read_bytes() == f1.read_bytes()
    assert (dest_dir / "dtb.dtb").read_bytes() == f2.read_bytes()


# ─── T12-T14: SerialTransport, trigger_command, Sync Parity & CLI ──────────


@pytest.mark.asyncio
async def test_serial_transport_trigger_command_and_upload(tmp_path: Path) -> None:
    """T12: Проверка записи trigger_command, очистки буфера и загрузки через SerialTransport."""
    fw_file = tmp_path / "app.bin"
    fw_file.write_bytes(b"FIRMWARE_PAYLOAD_12345")

    pair = MockAsyncSerialPair()
    mock_hw_serial = MagicMock()
    mock_hw_serial.is_open = True
    pair.writer_a.get_extra_info = MagicMock(return_value=mock_hw_serial)

    serial_mock = MagicMock()
    serial_mock.open_serial_connection = AsyncMock(return_value=(pair.b_to_a, pair.writer_a))

    # Эмулируем ответы загрузчика U-Boot для YMODEM:
    # 'C' (запрос Pkt0) -> ACK + 'C' (подтверждение Pkt0 и запрос данных) -> ACK (данные)
    # -> NAK (на первый EOT) -> ACK + 'C' (на второй EOT) -> ACK (на финальный Null Pkt0)
    pair.b_to_a.feed_data(CRC_CHR + ACK + CRC_CHR + ACK + NAK + ACK + CRC_CHR + ACK)

    with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
        cfg = ConnectionConfig(transport="serial", options={"device": "/dev/ttyUSB0", "baudrate": 115200})
        transport = SerialTransport(cfg)
        await transport.connect()

        sent = await transport.upload_ymodem(
            fw_file,
            trigger_command="loady 0x82000000",
            trigger_delay=0.01,
        )

        assert sent == len(b"FIRMWARE_PAYLOAD_12345")
        mock_hw_serial.reset_input_buffer.assert_called()
        assert pair.a_written[0] == b"loady 0x82000000\r"


def test_sync_connection_parity_and_pool_fan_out(tmp_path: Path) -> None:
    """T13: Проверка SyncConnection.files.upload_ymodem / upload_xmodem и PoolFileOperationsService."""
    fw_file = tmp_path / "sync_fw.bin"
    fw_file.write_bytes(b"SYNC_MODEM_DATA")

    async def _fake_open_serial(**_kwargs: object) -> tuple[asyncio.StreamReader, MagicMock]:
        pair = MockAsyncSerialPair()
        pair.b_to_a.feed_data(CRC_CHR + ACK + ACK)
        return (pair.b_to_a, pair.writer_a)

    serial_mock = MagicMock()
    serial_mock.open_serial_connection = AsyncMock(side_effect=_fake_open_serial)

    with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
        with SyncConnection.from_uri("serial:///dev/ttyUSB0?baudrate=115200") as sync_conn:
            sent = sync_conn.files.upload_xmodem(
                fw_file,
                mode="crc",
                trigger_command="loadx",
                trigger_delay=0.0,
            )
            assert sent == len(b"SYNC_MODEM_DATA")


@pytest.mark.asyncio
async def test_non_serial_transport_raises_capability_not_supported(tmp_path: Path) -> None:
    """Вызов upload_xmodem / upload_ymodem на LocalTransport выбрасывает CapabilityNotSupportedError."""
    f = tmp_path / "test.bin"
    f.write_bytes(b"123")

    async with Connection.from_uri("local://") as conn:
        with pytest.raises(CapabilityNotSupportedError, match="XMODEM upload is not supported"):
            await conn.files.upload_xmodem(f)
        with pytest.raises(CapabilityNotSupportedError, match="YMODEM upload is not supported"):
            await conn.files.upload_ymodem(f)
        with pytest.raises(CapabilityNotSupportedError, match="XMODEM download is not supported"):
            await conn.files.download_xmodem(f)
        with pytest.raises(CapabilityNotSupportedError, match="YMODEM download is not supported"):
            await conn.files.download_ymodem(tmp_path)


@pytest.mark.asyncio
async def test_pool_upload_ymodem(tmp_path: Path) -> None:
    """Проверка параллельной загрузки прошивки через ConnectionPool.files.upload_ymodem."""
    fw = tmp_path / "board.bin"
    fw.write_bytes(b"BOARD_FW")

    c1 = MagicMock(spec=Connection)
    c1.config = ConnectionConfig(transport="serial", host="COM1")
    c1.files = MagicMock()
    c1.files.upload_ymodem = AsyncMock(return_value=8)
    c1.__aenter__ = AsyncMock(return_value=c1)
    c1.__aexit__ = AsyncMock(return_value=None)

    c2 = MagicMock(spec=Connection)
    c2.config = ConnectionConfig(transport="serial", host="COM2")
    c2.files = MagicMock()
    c2.files.upload_ymodem = AsyncMock(return_value=8)
    c2.__aenter__ = AsyncMock(return_value=c2)
    c2.__aexit__ = AsyncMock(return_value=None)

    async with ConnectionPool([c1, c2]) as pool:
        res = await pool.files.upload_ymodem(fw, trigger_command="loady")
        assert res == {"COM1": 8, "COM2": 8}


@pytest.mark.asyncio
async def test_zmodem_adapter_missing_binary_and_mocked_exec(tmp_path: Path) -> None:
    """Проверка ZmodemSubprocessAdapter при отсутствии и наличии бинарников sz/rz."""
    fw = tmp_path / "z.bin"
    fw.write_bytes(b"ZMODEM_TEST")

    with patch("shutil.which", return_value=None):
        assert ZmodemSubprocessAdapter.is_available() is False
        with pytest.raises(CapabilityNotSupportedError, match="lrzsz"):
            await ZmodemSubprocessAdapter.send_file("/dev/ttyUSB0", 115200, fw)

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))

    with (
        patch("shutil.which", return_value="/usr/bin/sz"),
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)),
    ):
        assert ZmodemSubprocessAdapter.is_available() is True
        size = await ZmodemSubprocessAdapter.send_file("/dev/ttyUSB0", 115200, fw)
        assert size == len(b"ZMODEM_TEST")

    # Проверка ошибки при ненулевом коде возврата sz
    mock_proc.returncode = 1
    mock_proc.communicate = AsyncMock(return_value=(b"", b"Transfer aborted"))
    with (
        patch("shutil.which", return_value="/usr/bin/sz"),
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)),
        pytest.raises(ModemTransferError, match="Transfer aborted"),
    ):
        await ZmodemSubprocessAdapter.send_file("/dev/ttyUSB0", 115200, fw)


@pytest.mark.asyncio
async def test_serial_transport_generic_upload_and_download_routing(tmp_path: Path) -> None:
    """Проверка маршрутизации SerialTransport.upload() и download() по параметру protocol."""
    fw = tmp_path / "image.bin"
    fw.write_bytes(b"IMAGE")

    pair = MockAsyncSerialPair()
    serial_mock = MagicMock()
    serial_mock.open_serial_connection = AsyncMock(return_value=(pair.b_to_a, pair.writer_a))

    with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
        cfg = ConnectionConfig(transport="serial", options={"device": "/dev/ttyUSB0"})
        transport = SerialTransport(cfg)
        await transport.connect()

        with patch.object(transport, "upload_ymodem", AsyncMock(return_value=5)) as mock_ym:
            await transport.upload(str(fw), "", protocol="auto", trigger_command="loady")
            mock_ym.assert_awaited_once_with(str(fw), trigger_command="loady")

        with patch.object(transport, "upload_xmodem", AsyncMock(return_value=5)) as mock_xm:
            await transport.upload(str(fw), "", protocol="xmodem", xmodem_mode="crc", trigger_command="loadx")
            mock_xm.assert_awaited_once_with(str(fw), mode="crc", trigger_command="loadx")

        with pytest.raises(ModemProtocolError, match="Unsupported serial file transfer protocol"):
            await transport.upload(str(fw), "", protocol="kermit")


@pytest.mark.asyncio
async def test_xmodem_checksum_mode_waits_for_nak_when_receiver_sends_c() -> None:
    """Если явно запрошен mode='checksum', отправитель игнорирует начальные 'C' до получения NAK."""
    pair = MockAsyncSerialPair()
    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=2.0)

    # Приемник сначала шлет 'C' (просит CRC), а затем переключается на NAK (checksum)
    pair.b_to_a.feed_data(CRC_CHR + CRC_CHR + NAK + ACK + ACK)

    payload = b"ChecksumFallbackTest"
    sent = await sender.send(io.BytesIO(payload), total_size=len(payload), mode="checksum")
    assert sent == len(payload)
    # Пакет SOH (1) + seq(2) + data(128) + checksum(1) + EOT(1) = 133 байта
    tx_data = await pair.a_to_b.readexactly(133)
    assert tx_data[:1] == SOH
    assert tx_data[-1:] == EOT


@pytest.mark.asyncio
async def test_xmodem_receiver_preserves_sub_in_middle_chunks_and_strips_only_last() -> None:
    """Потоковый приемник XMODEM не удаляет 0x1A в промежуточных блоках, а обрезает только хвост последнего."""
    pair = MockAsyncSerialPair()
    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=2.0, handshake_timeout=2.0)
    receiver = AsyncXmodemReceiver(pair.a_to_b, pair.writer_b, packet_timeout=2.0)

    # Первый 128-байтный блок заканчивается на 0x1A (это полезные данные, НЕ паддинг!),
    # второй блок содержит 10 байт данных и будет дополнен 0x1A до 128 байт.
    block1 = b"A" * 120 + SUB * 8
    block2 = b"FINAL_DATA"
    original = block1 + block2

    in_buf = io.BytesIO(original)
    out_buf = io.BytesIO()

    await asyncio.gather(
        sender.send(in_buf, total_size=len(original), mode="crc"),
        receiver.receive(out_buf, mode="crc", strip_padding=True),
    )
    assert out_buf.getvalue() == original


@pytest.mark.asyncio
async def test_ymodem_zero_byte_file_and_batch_transfer(tmp_path: Path) -> None:
    """Передача пустого файла (0 байт) по YMODEM без дедлока на фазе EOT."""
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    non_empty = tmp_path / "data.bin"
    non_empty.write_bytes(b"hello")
    dest_dir = tmp_path / "out"

    pair = MockAsyncSerialPair()
    sender = AsyncYmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=2.0, handshake_timeout=2.0)
    receiver = AsyncYmodemReceiver(pair.a_to_b, pair.writer_b, packet_timeout=2.0)

    sent_total, received_paths = await asyncio.gather(
        sender.send_batch([empty_file, non_empty]),
        receiver.receive_batch(dest_dir),
    )

    assert sent_total == 5
    assert len(received_paths) == 2
    assert (dest_dir / "empty.bin").read_bytes() == b""
    assert (dest_dir / "data.bin").read_bytes() == b"hello"


@pytest.mark.asyncio
async def test_xmodem_cancel_event_aborts_and_sends_can() -> None:
    """Установка cancel_event немедленно прерывает передачу и отправляет последовательность CAN."""
    pair = MockAsyncSerialPair()
    sender = AsyncXmodemSender(pair.b_to_a, pair.writer_a, packet_timeout=1.0, handshake_timeout=1.0)
    cancel_ev = asyncio.Event()
    cancel_ev.set()

    with pytest.raises(ModemCancelledError, match="cancel_event"):
        await sender.send(io.BytesIO(b"data"), total_size=4, cancel_event=cancel_ev)

    tx = await pair.a_to_b.read(16)
    assert tx.count(CAN) >= 2

