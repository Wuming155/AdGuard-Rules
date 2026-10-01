"""规则解析器模块 — 负责单行规则识别与域名提取"""

import re
import ipaddress
import logging
from .config import RuleConfig

logger = logging.getLogger(__name__)


class RuleResolver:
    """规则解析器"""

    # 以 # 开头的有效规则前缀（非注释）
    VALID_HASH_PREFIXES = (
        '##', '#@#', '#?#', '#@?#',
        '#$#', '#@$#', '#$?#', '#@$?#',
        '#%#', '#@%#',
    )

    def __init__(self, rule_config: RuleConfig = None):
        """初始化规则解析器。

        :param rule_config: RuleConfig 规则配置，None 时使用默认值
        """
        # --- 使用专题配置（优于注入整个 Config） ---
        self._rule_config = rule_config or RuleConfig()

        # 匹配合法域名
        self.domain_pattern = re.compile(
            r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
        )

        # 预编译 AdGuard 语法标记正则
        self._rule_marker_re = re.compile(
            r'\|\||\*|\^|\$|##|#%#|#@#|#\?#|#@\?|#@%'
        )

        # 预编译 hosts IP 前缀正则
        self._hosts_ip_re = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::(?:[01])?)')

    @property
    def hosts_ip(self) -> str:
        """当前使用的 Hosts 重定向 IP。"""
        return self._rule_config.hosts_ip

    @staticmethod
    def is_ip(value: str) -> bool:
        """判断字符串是否为 IP 地址（IPv4 或 IPv6）。"""
        if not value or (value[0] not in '0123456789:'):
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # 核心解析
    # ------------------------------------------------------------------

    def resolve(self, line: str) -> tuple[str | None, str | None]:
        """解析单行规则，返回 (规则类型, 规范化规则) 或 (None, None)。

        规则类型包括：
            'adguard_rules'  — AdGuard 语法规则
            'hosts_rules'    — Hosts 格式规则
            'whitelist'      — 白名单规则
        """
        line = line.strip()

        # 1. 排除空行、注释行
        if not line:
            return None, None
        if line.startswith('!'):
            return None, None
        if line.startswith('#') and not line.startswith(self.VALID_HASH_PREFIXES):
            return None, None

        # 2. 白名单
        if line.startswith('@@'):
            return 'whitelist', line

        # 3. AdGuard 特色语法
        if self._rule_marker_re.search(line):
            if not self._hosts_ip_re.match(line):
                return 'adguard_rules', line

        # 4. Hosts 格式（用 ipaddress 精确判断 IP 前缀）
        first_part = line.split(None, 1)[0] if ' ' in line.strip() else ''
        if first_part:
            try:
                ip = ipaddress.ip_address(first_part)
                if ip.is_unspecified or ip.is_loopback:
                    parts = line.split(None, 2)
                    if len(parts) >= 2:
                        target = parts[1].strip().lower()
                        if target not in ('localhost', 'localhost.localdomain') and not self.is_ip(target):
                            return 'hosts_rules', f"{self._rule_config.hosts_ip} {target}"
                    return None, None
            except ValueError:
                pass

        # 5. 纯域名格式
        if self.domain_pattern.match(line):
            domain = line.lower()
            if not self.is_ip(domain):
                return 'hosts_rules', f"{self._rule_config.hosts_ip} {domain}"

        # 6. URL 路径类型
        if '/' in line and not self._hosts_ip_re.match(line):
            slash_idx = line.index('/')
            domain_part = line[:slash_idx]
            if domain_part and self.domain_pattern.match(domain_part):
                return 'adguard_rules', line
            if line.startswith('/'):
                return 'adguard_rules', line

        return None, None
