"""Central registry of rule metadata (id -> human-readable title)."""

RULES = {
    "MCP001": "Prompt-injection phrasing in tool description",
    "MCP002": "Hidden/invisible unicode characters in tool description",
    "MCP003": "Suspiciously long tool description (payload smuggling risk)",
    "MCP004": "Over-broad capability exposed by tool name/description",
    "MCP005": "Tool schema accepts arbitrary/unvalidated input",
    "MCP006": "Concealed or exfiltrative prompt/resource description",
    "MCP007": "Nested tool schema accepts arbitrary fields",
    "MCP101": "Dangerous code execution sink",
    "MCP102": "Shell command built from untrusted input",
    "MCP103": "Unsafe deserialization",
    "MCP104": "Aliased subprocess call with shell execution enabled",
    "MCP201": "Hardcoded secret or credential",
    "MCP202": "Hardcoded AI or cloud provider API key",
    "MCP301": "Server bound to all network interfaces",
    "MCP302": "Authentication / trust check disabled",
    "MCP303": "MCP server package is not pinned to an exact version",
    "MCP304": "MCP server downloads and executes a remote script",
    "MCP305": "MCP server uses unencrypted remote HTTP",
    "MCP306": "MCP server runs with elevated privileges or broad filesystem access",
}
