# tests/integration/test_ssh.py
import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_for_logs
from uniconn import Connection

@pytest.fixture(scope="module")
def ssh_container():
    """Docker контейнер с SSH сервером"""
    container = DockerContainer("linuxserver/openssh-server:latest") \
        .with_env("PASSWORD_ACCESS", "true") \
        .with_env("USER_NAME", "testuser") \
        .with_env("USER_PASSWORD", "testpass") \
        .with_exposed_ports(22)
    
    container.start()
    wait_for_logs(container, ".*sshd.*", timeout=30)
    
    host = container.get_container_host_ip()
    port = container.get_exposed_port(22)
    
    yield f"ssh://testuser:testpass@{host}:{port}"
    
    container.stop()

@pytest.mark.asyncio
@pytest.mark.integration
async def test_real_ssh_connection(ssh_container):
    """Интеграционный тест с реальным SSH сервером"""
    async with Connection.from_uri(ssh_container) as conn:
        result = await conn.run("echo hello")
        assert "hello" in result.stdout
        assert result.exit_code == 0

@pytest.mark.asyncio
@pytest.mark.integration
async def test_ssh_command_failure(ssh_container):
    """Тест обработки ошибок выполнения"""
    from uniconn.exceptions import ExecutionError
    
    async with Connection.from_uri(ssh_container) as conn:
        result = await conn.run("exit 1", raise_on_error=False)
        assert result.exit_code == 1
        
        with pytest.raises(ExecutionError):
            await conn.run("exit 1", raise_on_error=True)