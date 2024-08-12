from dataclasses import dataclass, field, asdict

# types
from typing import List, Literal


@dataclass
class Entrie:
    """OptConfig.entries one entrie
    """

    name: str
    """Name of key
    """

    key: str
    """Secret encrypted key
    """

    is_encrypted: bool
    """Is this key is encrypted
    """

    def to_dict(self):
        return asdict(self)


@dataclass
class OtpConfig:
    """Opt config data
    """

    version: int = 0
    """Ver
    """

    entries: List[Entrie] = field(default_factory=list)
    """List of encrypted migrations
    """

    def to_dict(self):
        return asdict(self)


@dataclass
class UrlScheme:
    """Url migration link provided by user
    """

    type: Literal['google', 'default']
    """Types of migration links
    """

    url: str
    """Migration link
    """
