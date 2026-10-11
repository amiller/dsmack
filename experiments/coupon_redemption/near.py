"""NEAR management adapter. No implicit retries and no credential logging.

The transport is injected: the experiment supplies a mock, while a future live
runner must supply authenticated HTTPS with no redirects and bounded timeouts.
Transport signature: (method, full_url, bearer, json_body) -> decoded JSON.
"""

from urllib.parse import urlencode
from uuid import UUID

from .spike import IssuedKey, RedemptionError


class Near:
    BASE = "https://cloud-api.near.ai/v1"

    def __init__(self, workspace_id, organization_id, session_jwt, reporting_token, transport):
        self.workspace_id = str(UUID(workspace_id))
        self.organization_id = str(UUID(organization_id))
        self._session = session_jwt
        self._reporting = reporting_token
        self._transport = transport

    def create_key(self, name, budget):
        # Management JWT is necessary; sk- inference keys cannot mint children.
        # Keep the returned secret in memory only until encrypted delivery.
        result = self._transport("POST", f"{self.BASE}/workspaces/{self.workspace_id}/api-keys",
                                 self._session, {"name": name, "spendLimit": {
                                     "amount": budget, "currency": "USD"}})
        if (not isinstance(result, dict) or not isinstance(result.get("id"), str)
                or not isinstance(result.get("key"), str) or not result["key"]):
            raise RedemptionError("invalid provider response")
        return IssuedKey(result["id"], result["key"])

    def usage_rows(self, key_id, start_time, end_time):
        """Fetch a fixed-window export, including platform service charges.

        Transport/provider are trusted for observations only. Organization-wide
        reporting credential privileges exceed this query's key filter.
        """
        params = {"api_key_id": str(UUID(key_id)), "workspace_id": self.workspace_id,
                  "start_time": start_time, "end_time": end_time, "source": "all", "limit": 1000}
        seen = set()
        rows = []
        for _ in range(1000):
            result = self._transport("GET", f"{self.BASE}/organizations/{self.organization_id}/usage/export?"
                                     + urlencode(params), self._reporting, None)
            if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                raise RedemptionError("invalid usage export")
            for row in result["data"]:
                if (not isinstance(row, dict) or row.get("api_key_id") != key_id
                        or row.get("workspace_id") != self.workspace_id):
                    raise RedemptionError("provider export attribution mismatch")
            rows.extend(result["data"])
            cursor = result.get("next_cursor")
            if cursor is None:
                return rows
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise RedemptionError("invalid usage cursor")
            seen.add(cursor)
            params["cursor"] = cursor
        raise RedemptionError("export exceeds bounded page count")
