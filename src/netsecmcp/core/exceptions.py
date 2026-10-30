class NetSecMCPError(RuntimeError):
    """Base error for NetSecMCP."""


class TargetAuthorizationError(NetSecMCPError):
    """Raised when a target is not authorized for scanning."""


class ExecutionPolicyError(NetSecMCPError):
    """Raised when a command does not satisfy the execution policy."""


class ScanValidationError(NetSecMCPError):
    """Raised when a scan profile or target range is invalid."""
