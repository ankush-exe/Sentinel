from sentinel_appsec.scan import scan_target


class Scanner:
	"""Public scanner facade with configurable request timeout."""

	def __init__(self, timeout: float = 10.0):
		if timeout <= 0:
			raise ValueError("timeout must be greater than zero")
		self.timeout = timeout

	async def scan(self, target_url: str) -> dict:
		return await scan_target(target_url, timeout=self.timeout)


__all__ = ["Scanner", "scan_target"]
