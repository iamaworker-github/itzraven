"""
Auth handling — YAML-based auth profiles with login flow, 2FA/TOTP, SSO.

Shannon-inspired: configure complex auth scenarios declaratively in YAML.
Supports form login, basic auth, OAuth2, SAML SSO, and TOTP-based 2FA.

Auth profiles are loaded from YAML and executed via BrowserAutomation
to capture authenticated sessions for scanning.
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from itzraven.core.logger import get_logger

logger = get_logger()

AUTH_PROFILES_DIR = Path.home() / ".itzraven" / "auth-profiles"


@dataclass
class AuthProfile:
    """Complete auth profile loaded from YAML configuration."""

    name: str
    type: str = "form"  # form, basic, oauth2, saml, header, cookie
    url: str = ""
    login_url: str = ""
    logout_url: str = ""
    fields: Dict[str, str] = field(default_factory=lambda: {
        "username": "username",
        "password": "password",
        "totp": "totp_code",
        "csrf": "csrf_token",
    })
    credentials: Dict[str, str] = field(default_factory=lambda: {
        "username": "",
        "password": "",
    })
    totp_secret: Optional[str] = None
    oauth2: Dict[str, str] = field(default_factory=lambda: {
        "client_id": "",
        "client_secret": "",
        "token_url": "",
        "scopes": "openid profile",
    })
    saml: Dict[str, str] = field(default_factory=lambda: {
        "idp_url": "",
        "sp_entity_id": "",
        "cert_path": "",
    })
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    session_cookie_name: Optional[str] = None
    pre_login_js: Optional[str] = None
    post_login_js: Optional[str] = None
    verify_url: Optional[str] = None
    verify_selector: Optional[str] = None
    max_retries: int = 3
    delay_between_retries: float = 2.0

    def resolve_credentials(self) -> Dict[str, str]:
        resolved = {}
        for key, value in self.credentials.items():
            if value.startswith("env:"):
                resolved[key] = os.getenv(value[4:], "")
            elif value.startswith("file:"):
                try:
                    resolved[key] = Path(value[5:]).read_text().strip()
                except Exception:
                    resolved[key] = ""
            else:
                resolved[key] = value
        return resolved

    def get_totp_code(self) -> Optional[str]:
        if not self.totp_secret:
            return None
        secret = self.totp_secret
        if secret.startswith("env:"):
            secret = os.getenv(secret[4:], "")
        if not secret:
            return None
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.now()
        except ImportError:
            logger.warning("pyotp not installed; TOTP unavailable")
            return None
        except Exception as e:
            logger.warning(f"TOTP generation failed: {e}")
            return None

    def to_dict(self) -> dict:
        base = asdict(self)
        base.pop("totp_secret", None)
        base.pop("oauth2", None)
        safe_creds = {}
        for k, v in self.credentials.items():
            if v.startswith("env:") or v.startswith("file:"):
                safe_creds[k] = v
            else:
                safe_creds[k] = "***"
        base["credentials"] = safe_creds
        return base


class AuthProfileManager:
    """Loads and manages YAML auth profiles."""

    def __init__(self, profiles_dir: Optional[Path] = None):
        self._dir = Path(profiles_dir or AUTH_PROFILES_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._profiles: Dict[str, AuthProfile] = {}
        self._load_all()

    def _load_all(self) -> None:
        for yaml_file in self._dir.glob("*.yaml"):
            try:
                profile = self._load_yaml(yaml_file)
                if profile:
                    self._profiles[profile.name] = profile
            except Exception as e:
                logger.debug(f"Failed to load auth profile {yaml_file.name}: {e}")

    def _load_yaml(self, path: Path) -> Optional[AuthProfile]:
        try:
            import yaml as _yaml
        except ImportError:
            logger.warning("PyYAML not installed; install with: pip install pyyaml")
            return None

        with open(path) as f:
            data = _yaml.safe_load(f)

        if not data or "name" not in data:
            return None

        return AuthProfile(
            name=data.get("name", path.stem),
            type=data.get("type", "form"),
            url=data.get("url", ""),
            login_url=data.get("login_url", data.get("url", "")),
            logout_url=data.get("logout_url", ""),
            fields=data.get("fields", {}),
            credentials=data.get("credentials", {}),
            totp_secret=data.get("totp_secret"),
            oauth2=data.get("oauth2", {}),
            saml=data.get("saml", {}),
            headers=data.get("headers", {}),
            cookies=data.get("cookies", {}),
            session_cookie_name=data.get("session_cookie_name"),
            pre_login_js=data.get("pre_login_js"),
            post_login_js=data.get("post_login_js"),
            verify_url=data.get("verify_url"),
            verify_selector=data.get("verify_selector"),
            max_retries=data.get("max_retries", 3),
            delay_between_retries=data.get("delay_between_retries", 2.0),
        )

    def get_profile(self, name: str) -> Optional[AuthProfile]:
        return self._profiles.get(name)

    def list_profiles(self) -> List[dict]:
        return [p.to_dict() for p in self._profiles.values()]

    def create_from_yaml(self, yaml_content: str) -> Optional[AuthProfile]:
        try:
            import yaml as _yaml
            data = _yaml.safe_load(yaml_content)
        except Exception:
            return None

        if not data or "name" not in data:
            return None

        profile = AuthProfile(
            name=data["name"],
            type=data.get("type", "form"),
            url=data.get("url", ""),
            login_url=data.get("login_url", data.get("url", "")),
            fields=data.get("fields", {}),
            credentials=data.get("credentials", {}),
            totp_secret=data.get("totp_secret"),
            headers=data.get("headers", {}),
            session_cookie_name=data.get("session_cookie_name"),
        )

        filepath = self._dir / f"{profile.name}.yaml"
        filepath.write_text(yaml_content)
        self._profiles[profile.name] = profile
        logger.info(f"Auth profile '{profile.name}' created at {filepath}")
        return profile


class AuthFlowExecutor:
    """Executes auth flows via BrowserAutomation to capture sessions."""

    def __init__(self, profile: AuthProfile):
        self._profile = profile
        self._session_cookies: Dict[str, str] = {}
        self._session_headers: Dict[str, str] = {}
        self._authenticated = False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    async def execute(self, browser=None) -> bool:
        """Execute the auth flow. Optionally pass a shared browser instance."""
        if browser is None:
            from itzraven.toolkit import BrowserAutomation
            browser = BrowserAutomation()

        profile = self._profile
        logger.info(f"Executing auth flow: {profile.name} ({profile.type})")

        for attempt in range(profile.max_retries):
            try:
                if profile.type == "form":
                    success = await self._do_form_login(browser)
                elif profile.type == "basic":
                    success = await self._do_basic_auth(browser)
                elif profile.type == "oauth2":
                    success = await self._do_oauth2(browser)
                elif profile.type == "header":
                    success = await self._do_header_auth(browser)
                elif profile.type == "cookie":
                    success = await self._do_cookie_auth(browser)
                else:
                    logger.warning(f"Unknown auth type: {profile.type}")
                    return False

                if success:
                    self._authenticated = True
                    return True

            except Exception as e:
                logger.warning(f"Auth attempt {attempt + 1} failed: {e}")

            if attempt < profile.max_retries - 1:
                await asyncio.sleep(profile.delay_between_retries)

        logger.error(f"Auth flow '{profile.name}' failed after {profile.max_retries} attempts")
        return False

    async def _do_form_login(self, browser) -> bool:
        import asyncio
        profile = self._profile
        creds = profile.resolve_credentials()

        await browser.goto(profile.login_url or profile.url)
        await asyncio.sleep(1)

        if profile.pre_login_js:
            await browser.page.evaluate(profile.pre_login_js)

        username_field = profile.fields.get("username", "username")
        password_field = profile.fields.get("password", "password")

        await browser.page.fill(f'[name="{username_field}"]', creds.get("username", ""))
        await browser.page.fill(f'[name="{password_field}"]', creds.get("password", ""))

        totp_code = profile.get_totp_code()
        if totp_code:
            totp_field = profile.fields.get("totp", "totp_code")
            await browser.page.fill(f'[name="{totp_field}"]', totp_code)

        csrf_field = profile.fields.get("csrf")
        if csrf_field:
            csrf_value = await browser.page.evaluate(
                f"document.querySelector('[name={csrf_field}]')?.value || ''"
            )
            if csrf_value:
                self._session_headers["X-CSRF-Token"] = csrf_value

        submit_btn = profile.fields.get("submit", 'button[type="submit"]')
        await browser.page.click(submit_btn)
        await asyncio.sleep(2)

        if profile.post_login_js:
            await browser.page.evaluate(profile.post_login_js)

        cookies = await browser.page.cookies()
        for c in cookies:
            self._session_cookies[c["name"]] = c["value"]

        return await self._verify_auth(browser)

    async def _do_basic_auth(self, browser) -> bool:
        creds = self._profile.resolve_credentials()
        username = creds.get("username", "")
        password = creds.get("password", "")
        auth_url = self._profile.url.replace(
            "://", f"://{username}:{password}@"
        )
        await browser.goto(auth_url)
        await asyncio.sleep(1)
        return await self._verify_auth(browser)

    async def _do_oauth2(self, browser) -> bool:
        profile = self._profile
        oauth = profile.oauth2
        auth_url = (
            f"{oauth.get('token_url', profile.url)}"
            f"?client_id={oauth.get('client_id', '')}"
            f"&response_type=code"
            f"&scope={oauth.get('scopes', 'openid')}"
        )
        await browser.goto(auth_url)
        await asyncio.sleep(2)

        creds = profile.resolve_credentials()
        username_field = profile.fields.get("username", "username")
        password_field = profile.fields.get("password", "password")
        await browser.page.fill(f'[name="{username_field}"]', creds.get("username", ""))
        await browser.page.fill(f'[name="{password_field}"]', creds.get("password", ""))
        submit_btn = profile.fields.get("submit", 'button[type="submit"]')
        await browser.page.click(submit_btn)
        await asyncio.sleep(2)

        cookies = await browser.page.cookies()
        for c in cookies:
            self._session_cookies[c["name"]] = c["value"]
        return await self._verify_auth(browser)

    async def _do_header_auth(self, browser) -> bool:
        profile = self._profile
        await browser.goto(profile.url)
        await asyncio.sleep(1)
        for key, value in profile.headers.items():
            resolved = value
            if resolved.startswith("env:"):
                resolved = os.getenv(resolved[4:], "")
            self._session_headers[key] = resolved
        return True

    async def _do_cookie_auth(self, browser) -> bool:
        profile = self._profile
        await browser.goto(profile.url)
        for key, value in profile.cookies.items():
            resolved = value
            if resolved.startswith("env:"):
                resolved = os.getenv(resolved[4:], "")
            await browser.page.evaluate(
                f"document.cookie = '{key}={resolved}; path=/';"
            )
            self._session_cookies[key] = resolved
        await browser.goto(profile.url)
        await asyncio.sleep(1)
        return await self._verify_auth(browser)

    async def _verify_auth(self, browser) -> bool:
        profile = self._profile
        if profile.verify_url:
            await browser.goto(profile.verify_url)
            await asyncio.sleep(1)
            if profile.verify_selector:
                try:
                    el = await browser.page.query_selector(profile.verify_selector)
                    return el is not None
                except Exception:
                    return False
            return True
        return bool(self._session_cookies) or bool(self._session_headers)

    def get_session_dict(self) -> Dict[str, Any]:
        return {
            "cookies": self._session_cookies,
            "headers": self._session_headers,
            "profile": self._profile.name,
        }


# Sample auth profile YAML for reference:
SAMPLE_AUTH_YAML = """# Auth profile for form-based login with optional 2FA
name: myapp-login
type: form
url: https://app.example.com
login_url: https://app.example.com/login
fields:
  username: email
  password: password
  totp: otp
  submit: 'button[type="submit"]'
credentials:
  username: admin@example.com
  password: env:AUTH_PASSWORD  # reads from env var AUTH_PASSWORD
totp_secret: env:TOTP_SECRET   # optional, for 2FA
session_cookie_name: sessionid
verify_url: https://app.example.com/dashboard
verify_selector: '.user-profile'
"""


_profile_manager: Optional[AuthProfileManager] = None


def get_auth_profile_manager() -> AuthProfileManager:
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = AuthProfileManager()
    return _profile_manager
