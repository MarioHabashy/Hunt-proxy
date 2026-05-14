"""
Scans package — each module contains a mixin class with methods for one scan type.

Usage (in ScanWorker):
    from scans.xss_scan import XssScanMixin
    from scans.sqli_scan import SqliScanMixin
    ...

    class ScanWorker(QThread, XssScanMixin, SqliScanMixin, ...):
        ...
"""

from .xss_scan import XssScanMixin
from .sqli_scan import SqliScanMixin
from .lfi_scan import LfiScanMixin
from .cmdi_scan import CmdiScanMixin
from .idor_scan import IdorScanMixin
from .upload_scan import UploadScanMixin
from .sqli_helpers_scan import SqliHelpersMixin
from .ssrf_scan import SsrfScanMixin
from .xxe_scan import XxeScanMixin
from .nosqli_scan import NoSqliScanMixin
from .bypass_scan import BypassScanMixin
from .cors_scan import CorsScanMixin
from .open_redirect_scan import OpenRedirectScanMixin
from .ssti_scan import SstiScanMixin


__all__ = [
    "XssScanMixin",
    "SqliScanMixin",
    "LfiScanMixin",
    "CmdiScanMixin",
    "IdorScanMixin",
    "UploadScanMixin",
    "SqliHelpersMixin",
    "SsrfScanMixin",
    "XxeScanMixin",
    "NoSqliScanMixin",
    "BypassScanMixin",
    "CorsScanMixin",
    "OpenRedirectScanMixin",
    "SstiScanMixin",
]