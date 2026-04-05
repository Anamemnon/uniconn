# src/uniconn/_logging.py
import logging
import re
from typing import Optional

class SecretMaskingFilter(logging.Filter):
    """Фильтр для маскирования чувствительных данных в логах"""
    
    PATTERNS = [
        (re.compile(r'password[=:]\S+', re.IGNORECASE), 'password=***'),
        (re.compile(r'pass[=:]\S+', re.IGNORECASE), 'pass=***'),
        (re.compile(r'secret[=:]\S+', re.IGNORECASE), 'secret=***'),
        (re.compile(r'token[=:]\S+', re.IGNORECASE), 'token=***'),
        (re.compile(r'://[^:]+:[^@]+@', re.IGNORECASE), '://***:***@'),
    ]
    
    def __init__(self, name: str = ""):
        super().__init__(name)
        self._enabled = True
    
    def filter(self, record: logging.LogRecord) -> bool:
        if not self._enabled:
            return True
        
        # Маскирование message
        if isinstance(record.msg, str):
            for pattern, replacement in self.PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        
        # Маскирование args
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    self._mask_value(arg) for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: self._mask_value(v) for k, v in record.args.items()
                }
        
        return True
    
    def _mask_value(self, value) -> str:
        if isinstance(value, str):
            for pattern, replacement in self.PATTERNS:
                value = pattern.sub(replacement, value)
        return value


def get_logger(
    name: str = "uniconn",
    level: int = logging.INFO,
    mask_secrets: bool = True
) -> logging.Logger:
    """Получить logger с маскированием секретов"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if mask_secrets and not any(
        isinstance(f, SecretMaskingFilter) for f in logger.filters
    ):
        logger.addFilter(SecretMaskingFilter())
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(handler)
    
    return logger