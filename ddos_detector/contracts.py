"""Version-one ML input checks; no capture, labeling, or model execution."""
from collections.abc import Mapping
import math
from numbers import Real

from .config import FEATURE_NAMES

FEATURE_SCHEMA_VERSION = "1"
_COUNT_FIELDS = {"syn_count", "unique_src_ips"}
_FRACTION_FIELDS = {"syn_no_ack_share", "tcp_share", "udp_share", "icmp_share"}


def feature_vector(record: Mapping[str, Real], *, feature_schema_version: str):
    """Return finite floats in FEATURE_NAMES order or reject incompatible input.

    Zero-valued measured empty records are structurally valid; the caller must
    exclude empty/unavailable windows from training and inference as specified
    in docs/feature-contract.md. This cannot establish capture coverage.
    """
    if feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise ValueError("Unsupported feature schema version")
    if not isinstance(record, Mapping):
        raise ValueError("Feature record must be a mapping")
    if set(record) != set(FEATURE_NAMES):
        raise ValueError("Feature names must match the version-one contract exactly")
    values = []
    for name in FEATURE_NAMES:
        value = record[name]
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"{name} must be numeric")
        try:
            number = float(value)
        except (OverflowError, ValueError) as exc:
            raise ValueError(f"{name} must be finite") from exc
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"{name} must be finite and nonnegative")
        if name in _COUNT_FIELDS and value % 1 != 0:
            raise ValueError(f"{name} must be an integral count")
        if name in _FRACTION_FIELDS and number > 1:
            raise ValueError(f"{name} must be between zero and one")
        values.append(number)
    return tuple(values)
