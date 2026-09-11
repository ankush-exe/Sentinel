from sentinel_appsec.scan import scan_target


class Scanner:
	"""Public scanner facade for synchronous and asynchronous callers."""

	async def scan(self, target_url: str) -> dict:
		return await scan_target(target_url)


__all__ = ["Scanner", "scan_target"]
