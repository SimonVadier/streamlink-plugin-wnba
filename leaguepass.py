import logging
import re
from streamlink.plugin import Plugin, PluginError, pluginargument, pluginmatcher
from streamlink.plugin.api import validate
from streamlink.stream.hls import HLSStream

log = logging.getLogger(__name__)


@pluginmatcher(
    name="leaguepass",
    pattern=re.compile(
        r"https?://(?:www\.)?leaguepass\.wnba\.com/(?P<type>live|video)/(?P<video_id>\d+)"
    ),
)
@pluginargument(
    "email",
    requires=["password"],
    metavar="EMAIL",
    help="Email address for League Pass authentication",
)
@pluginargument(
    "password",
    sensitive=True,
    metavar="PASSWORD",
    help="Password for League Pass authentication",
)
class LeaguePass(Plugin):
    base_url = "https://dce-frontoffice.imggaming.com/api"
    init_url = f"{base_url}/v1/init"
    login_url = f"{base_url}/v2/login"
    live_info_url = f"{base_url}/v4/event/{{id}}"
    vod_info_url = f"{base_url}/v4/vod/{{id}}"

    app_js_url_re = re.compile(
        r"""<script[^>]*src="([^"]*app\.[^"]*\.js)"[^>]*></script>"""
    )
    app_api_key_re = re.compile(r'''API_KEY:\s*"([\w\-]+)"''')
    app_output_folder_re = re.compile(r'''OUTPUT_FOLDER:\s*"([\w\.\-]+)"''')

    _init_schema = validate.Schema(
        {
            "authentication": {
                "authorisationToken": str,
            },
        }
    )
    _login_schema = validate.Schema({"authorisationToken": str})
    _info_schema = validate.Schema(
        {validate.optional("playerUrlCallback"): validate.url(), "accessLevel": str}
    )
    _stream_schema = validate.Schema({"hlsUrl": validate.url()})
    _vod_schema = validate.Schema({"hls": [{"url": validate.url()}]})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.video_id = self.match["video_id"]
        self.isLive = self.match["type"] == "live"
        if not self.video_id:
            raise PluginError("Could not find video ID in URL")

    def _init_api_headers(self):
        res = self.session.http.get(self.url)
        js = self.app_js_url_re.search(res.text)
        if not js or not js.group(1):
            raise PluginError("Could not find app.js URL")
        log.debug("Found app.js URL: %s", js.group(1))

        res = self.session.http.get("https://leaguepass.wnba.com" + js.group(1))

        api_key = self.app_api_key_re.search(res.text)
        if not api_key or not api_key.group(1):
            raise PluginError("Could not find API key in app.js")
        log.debug("Found API key: %s", api_key.group(1))

        output_folder = self.app_output_folder_re.search(res.text)
        if not output_folder or not output_folder.group(1):
            raise PluginError("Could not find output folder in app.js")
        log.debug("Found output folder: %s", output_folder.group(1))

        self.session.http.headers.update(
            {
                "Realm": "dce.wnba",
                "X-Api-Key": api_key.group(1),
                "X-App-Var": output_folder.group(1),
            }
        )

        init_res = self.session.http.get(self.init_url)
        init_data = self.session.http.json(init_res, schema=self._init_schema)
        if not init_data:
            raise PluginError("Could not find init data")

        auth_token = init_data["authentication"]["authorisationToken"]

        self.session.http.headers.update(
            {
                "Authorization": f"Bearer {auth_token}",
            }
        )

    def _get_access_token(self):
        res = self.session.http.get(self.init_url)
        init_data = self.session.http.json(res, schema=self._init_schema)
        return init_data["authentication"]["authorisationToken"]

    def _authenticate(self, email, password):
        payload = {"id": email, "secret": password}
        res = self.session.http.post(self.login_url, json=payload)
        login_data = self.session.http.json(res, schema=self._login_schema)
        return login_data["authorisationToken"]

    def _get_info(self):
        url = self.live_info_url if self.isLive else self.vod_info_url
        params = (
            {"includePlaybackDetails": "URL", "displayGeoblocked": "SHOW"}
            if self.isLive
            else {
                "includePlaybackDetails": "URL",
            }
        )

        res = self.session.http.get(
            url=url.format(id=self.video_id),
            headers=self.session.http.headers,
            params=params,
        )
        return self.session.http.json(res, schema=self._info_schema)

    def _get_stream_url(self, info_url):
        res = self.session.http.get(info_url, headers=self.session.http.headers)
        return self.session.http.json(res, schema=self._stream_schema)

    def _get_vod_url(self, info_url):
        res = self.session.http.get(info_url, headers=self.session.http.headers)
        return self.session.http.json(res, schema=self._vod_schema)

    def _get_streams(self):
        self._init_api_headers()

        email = self.get_option("email")
        password = self.get_option("password")
        token = None
        if email and password:
            token = self._authenticate(email=email, password=password)
        else:
            token = self._get_access_token()

        self.session.http.headers.update({"Authorization": f"Bearer {token}"})

        info_data = self._get_info()
        if info_data["accessLevel"] != "GRANTED":
            raise PluginError("Access denied. Please check your credentials.")
        info_url = info_data["playerUrlCallback"]

        hls_url = None

        if self.isLive:
            stream_data = self._get_stream_url(info_url)
            hls_url = stream_data["hlsUrl"]
        else:
            vod_data = self._get_vod_url(info_url)
            hls_url = vod_data["hls"][0]["url"]

        return HLSStream.parse_variant_playlist(self.session, hls_url)


__plugin__ = LeaguePass
