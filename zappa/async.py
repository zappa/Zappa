import warnings

from .asynchronous import *  # noqa: F401

warnings.warn(
    'Module "zappa.async" is deprecated; please use "zappa.asynchronous" instead.',
    category=DeprecationWarning,
)
