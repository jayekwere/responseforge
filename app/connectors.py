from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import httpx
from pydantic import Field, TypeAdapter

from app.common import Contract, DomainError, digest

Json = dict[str, Any]


class TargetBase(Contract):
    alias: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    tenant: str = Field(pattern=r"^[a-z0-9-]{1,64}$")


class AwsTarget(TargetBase):
    provider: Literal["aws"]
    account: str = Field(pattern=r"^\d{12}$")
    profile: str = Field(min_length=1, max_length=128)
    username: str = Field(pattern=r"^responseforge-[A-Za-z0-9+=,.@_-]{1,49}$")
    user_id: str = Field(pattern=r"^AIDA[A-Z0-9]{12,124}$")
    access_key_id: str = Field(pattern=r"^AKIA[A-Z0-9]{16}$")


class AzureTarget(TargetBase):
    provider: Literal["azure"]
    directory_tenant: str = Field(pattern=r"^[a-f0-9-]{36}$")
    subscription: str = Field(pattern=r"^[a-f0-9-]{36}$")
    object_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    app_id: str = Field(pattern=r"^[a-f0-9-]{36}$")


class GcpTarget(TargetBase):
    provider: Literal["gcp"]
    project: str = Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    email: str = Field(
        pattern=r"^responseforge-[a-z0-9-]+@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com$"
    )
    unique_id: str = Field(pattern=r"^\d{10,30}$")
    operator_account: str = Field(pattern=r"^[^\s/]+@[^\s/]+$")


Target = Annotated[AwsTarget | AzureTarget | GcpTarget, Field(discriminator="provider")]
TARGETS = TypeAdapter(list[Target])


def physical(target: Target) -> str:
    if isinstance(target, AwsTarget):
        return digest(["aws", target.account, target.user_id, target.access_key_id])
    if isinstance(target, AzureTarget):
        return digest(["azure", target.directory_tenant, target.object_id])
    return digest(["gcp", target.project, target.unique_id])


class Registry:
    def __init__(self, targets: list[Target]):
        self.targets: dict[tuple[str, str], Target] = {}
        seen: set[str] = set()
        for target in targets:
            key = (target.tenant, target.alias)
            if key in self.targets or physical(target) in seen:
                raise ValueError("Duplicate alias or physical cloud target")
            if isinstance(target, GcpTarget) and not target.email.endswith(
                f"@{target.project}.iam.gserviceaccount.com"
            ):
                raise ValueError("GCP account must belong to the configured project")
            self.targets[key] = target
            seen.add(physical(target))

    @classmethod
    def load(cls, path: Path) -> Registry:
        if path.stat().st_mode & 0o077 or path.stat().st_size > 1048576:
            raise ValueError("Cloud target registry must be private and at most 1 MiB")
        return cls(TARGETS.validate_json(path.read_bytes(), strict=True))

    def get(self, tenant: str, alias: str) -> Target:
        target = self.targets.get((tenant, alias))
        if target is None:
            raise DomainError("Cloud target not found", 404)
        return target


def command(arguments: list[str]) -> Json:
    environment = {**os.environ, "AWS_MAX_ATTEMPTS": "1", "AWS_RETRY_MODE": "standard"}
    result = subprocess.run(
        arguments, capture_output=True, timeout=30, check=False, env=environment
    )
    if result.returncode or len(result.stdout) > 1048576:
        raise DomainError("Cloud credential or provider command failed", 502)
    value = json.loads(result.stdout or b"{}")
    if not isinstance(value, dict):
        raise DomainError("Invalid native provider response", 502)
    return value


class Connector(Protocol):
    def read(self) -> Json: ...
    def set_disabled(self, disabled: bool) -> None: ...


class AwsConnector:
    def __init__(self, target: AwsTarget, run: Callable[[list[str]], Json] = command):
        self.target, self.run = target, run

    def call(self, service: str, operation: str, parameters: Json) -> Json:
        if (service, operation) not in {
            ("sts", "get-caller-identity"),
            ("iam", "get-user"),
            ("iam", "list-access-keys"),
            ("iam", "update-access-key"),
        }:
            raise DomainError("Cloud operation rejected", 403)
        return self.run(
            [
                "aws",
                service,
                operation,
                "--profile",
                self.target.profile,
                "--region",
                "us-east-1",
                "--endpoint-url",
                "https://iam.amazonaws.com"
                if service == "iam"
                else "https://sts.us-east-1.amazonaws.com",
                "--cli-input-json",
                json.dumps(parameters),
                "--no-paginate",
                "--no-cli-pager",
                "--no-cli-auto-prompt",
                "--output",
                "json",
            ]
        )

    def read(self) -> Json:
        t = self.target
        caller = self.call("sts", "get-caller-identity", {})
        user = self.call("iam", "get-user", {"UserName": t.username})["User"]
        arn = str(user.get("Arn", ""))
        tags = {item["Key"]: item["Value"] for item in user.get("Tags", [])}
        if (
            caller.get("Account") != t.account
            or caller.get("Arn") in {arn, f"arn:aws:iam::{t.account}:root"}
            or not arn.startswith(f"arn:aws:iam::{t.account}:user/")
            or user.get("UserId") != t.user_id
            or user.get("UserName") != t.username
            or tags.get("responseforge-managed") != "true"
            or tags.get("responseforge-tenant") != t.tenant
        ):
            raise DomainError("AWS target identity, ownership or caller precondition failed", 403)
        response = self.call("iam", "list-access-keys", {"UserName": t.username, "MaxItems": 100})
        keys = [
            key
            for key in response.get("AccessKeyMetadata", [])
            if key.get("AccessKeyId") == t.access_key_id and key.get("UserName") == t.username
        ]
        if (
            response.get("IsTruncated", False)
            or len(keys) != 1
            or keys[0].get("Status") not in {"Active", "Inactive"}
        ):
            raise DomainError("Pinned AWS access key was not observed unambiguously", 409)
        return {
            "provider": "aws",
            "target": physical(t),
            "native_id": t.user_id,
            "key_id": t.access_key_id,
            "disabled": keys[0]["Status"] == "Inactive",
            "ownership": tags,
            "created_at": keys[0].get("CreateDate"),
        }

    def set_disabled(self, disabled: bool) -> None:
        self.call(
            "iam",
            "update-access-key",
            {
                "UserName": self.target.username,
                "AccessKeyId": self.target.access_key_id,
                "Status": "Inactive" if disabled else "Active",
            },
        )


class JsonHTTP:
    def __init__(self, token: str, host: str):
        self.token, self.host = token, host

    def __call__(self, method: str, url: str, payload: Json | None = None) -> Json:
        parsed = httpx.URL(url)
        if (
            parsed.scheme != "https"
            or parsed.host != self.host
            or parsed.port not in {None, 443}
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise DomainError("Cloud URL rejected", 403)
        # The default HTTP transport does not retry writes. Redirects remain disabled.
        with httpx.Client(timeout=20, follow_redirects=False) as client:
            with client.stream(
                method,
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            ) as response:
                if response.status_code not in {200, 204}:
                    raise DomainError(f"Cloud provider HTTP {response.status_code}", 502)
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > 1048576:
                        raise DomainError("Cloud provider response exceeds bound", 502)
        value = json.loads(data or b"{}")
        if not isinstance(value, dict):
            raise DomainError("Invalid native provider response", 502)
        return value


HttpCall = Callable[[str, str, Json | None], Json]


class AzureConnector:
    def __init__(
        self,
        target: AzureTarget,
        http: HttpCall | None = None,
        run: Callable[[list[str]], Json] = command,
    ):
        self.target, self.run, self.http = target, run, http

    def session(self) -> HttpCall:
        t = self.target
        context = self.run(
            ["az", "account", "show", "--subscription", t.subscription, "--output", "json"]
        )
        if (
            context.get("tenantId", "").lower() != t.directory_tenant
            or context.get("id", "").lower() != t.subscription
            or str(context.get("user", {}).get("name", "")).lower() in {t.object_id, t.app_id}
        ):
            raise DomainError("Azure context mismatch or self-disable attempt", 403)
        if self.http is None:
            token = self.run(
                [
                    "az",
                    "account",
                    "get-access-token",
                    "--subscription",
                    t.subscription,
                    "--resource",
                    "https://graph.microsoft.com/",
                    "--output",
                    "json",
                ]
            )["accessToken"]
            self.http = JsonHTTP(str(token), "graph.microsoft.com")
        return self.http

    def url(self) -> str:
        return f"https://graph.microsoft.com/v1.0/servicePrincipals/{self.target.object_id}"

    def read(self) -> Json:
        value = self.session()(
            "GET",
            self.url() + "?$select=id,appId,displayName,servicePrincipalType,accountEnabled,tags",
            None,
        )
        t = self.target
        if (
            value.get("id") != t.object_id
            or value.get("appId") != t.app_id
            or value.get("servicePrincipalType") != "Application"
            or not str(value.get("displayName", "")).startswith("responseforge-")
            or not isinstance(value.get("accountEnabled"), bool)
            or not {"responseforge-managed", f"responseforge-tenant:{t.tenant}"}.issubset(
                set(value.get("tags", []))
            )
        ):
            raise DomainError("Azure target identity or ownership precondition failed", 403)
        return {
            "provider": "azure",
            "target": physical(t),
            "native_id": t.object_id,
            "app_id": t.app_id,
            "disabled": not value["accountEnabled"],
            "ownership": sorted(value["tags"]),
        }

    def set_disabled(self, disabled: bool) -> None:
        self.session()("PATCH", self.url(), {"accountEnabled": not disabled})


class GcpConnector:
    def __init__(
        self,
        target: GcpTarget,
        http: HttpCall | None = None,
        run: Callable[[list[str]], Json] = command,
    ):
        self.target, self.http, self.run = target, http, run

    def session(self) -> HttpCall:
        t = self.target
        config = self.run(["gcloud", "config", "list", "--format=json"])
        impersonated = config.get("auth", {}).get("impersonate_service_account") or os.environ.get(
            "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"
        )
        if t.operator_account == t.email or impersonated:
            raise DomainError("GCP self-disable or implicit impersonation rejected", 403)
        if self.http is None:
            result = subprocess.run(
                [
                    "gcloud",
                    "auth",
                    "print-access-token",
                    "--account",
                    t.operator_account,
                    "--project",
                    t.project,
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode or not result.stdout.strip() or len(result.stdout) > 16384:
                raise DomainError("GCP authentication failed", 502)
            self.http = JsonHTTP(result.stdout.strip(), "iam.googleapis.com")
        return self.http

    def url(self) -> str:
        return f"https://iam.googleapis.com/v1/projects/{self.target.project}/serviceAccounts/{self.target.unique_id}"

    def read(self) -> Json:
        t = self.target
        value = self.session()("GET", self.url(), None)
        if (
            value.get("uniqueId") != t.unique_id
            or value.get("email") != t.email
            or value.get("projectId") != t.project
            or value.get("description") != f"responseforge-managed:{t.tenant}:{t.alias}"
            or not isinstance(value.get("disabled", False), bool)
        ):
            raise DomainError("GCP target identity or ownership precondition failed", 403)
        return {
            "provider": "gcp",
            "target": physical(t),
            "native_id": t.unique_id,
            "email": t.email,
            "disabled": value.get("disabled", False),
            "ownership": value["description"],
        }

    def set_disabled(self, disabled: bool) -> None:
        self.session()("POST", self.url() + (":disable" if disabled else ":enable"), {})


def connect(target: Target) -> Connector:
    if isinstance(target, AwsTarget):
        return AwsConnector(target)
    if isinstance(target, AzureTarget):
        return AzureConnector(target)
    return GcpConnector(target)
