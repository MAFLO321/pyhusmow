import argparse
import json
import logging
import pprint
import time
from configparser import ConfigParser
from datetime import datetime, timedelta
from dateutil.parser import parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

logger = logging.getLogger("main")


class AutoMowerConfig(ConfigParser):
    def __init__(self):
        super(AutoMowerConfig, self).__init__()
        self["husqvarna.net"] = {}
        self.login = ""
        self.password = ""
        self.log_level = "INFO"
        self.expire_status = "30"

    def load_config(self):
        return self.read("automower.cfg")

    def save_config(self):
        with open("automower.cfg", mode="w") as f:
            return self.write(f)

    @property
    def login(self):
        return self["husqvarna.net"]["login"]

    @login.setter
    def login(self, value):
        self["husqvarna.net"]["login"] = value

    @property
    def password(self):
        return self["husqvarna.net"]["password"]

    @password.setter
    def password(self, value):
        self["husqvarna.net"]["password"] = value

    @property
    def log_level(self):
        return self["husqvarna.net"]["log_level"]

    @log_level.setter
    def log_level(self, value):
        self["husqvarna.net"]["log_level"] = value

    @property
    def expire_status(self):
        return int(self["husqvarna.net"]["expire_status"])

    @expire_status.setter
    def expire_status(self, value):
        self["husqvarna.net"]["expire_status"] = str(value)


class TokenConfig(ConfigParser):
    def __init__(self):
        super(TokenConfig, self).__init__()
        self["husqvarna.net"] = {}
        self.token = ""
        self.provider = ""
        self.expire_on = datetime(1900, 1, 1)

    def load_config(self):
        return self.read("token.cfg")

    def save_config(self):
        with open("token.cfg", mode="w") as f:
            return self.write(f)

    @property
    def token(self):
        return self["husqvarna.net"]["token"]

    @token.setter
    def token(self, value):
        self["husqvarna.net"]["token"] = value

    @property
    def provider(self):
        return self["husqvarna.net"]["provider"]

    @provider.setter
    def provider(self, value):
        self["husqvarna.net"]["provider"] = value

    @property
    def expire_on(self):
        return parse(self["husqvarna.net"]["expire_on"])

    @expire_on.setter
    def expire_on(self, value):
        self["husqvarna.net"]["expire_on"] = value.isoformat()

    def token_valid(self):
        return True if self.token and self.expire_on > datetime.now() else False


class CommandException(Exception):
    pass


class API:
    _API_IM = "https://iam-api.dss.husqvarnagroup.net/api/v3/"
    _API_APP = "https://amc-api.dss.husqvarnagroup.net/app/v1/"
    _HEADERS = {"Accept": "application/json", "Content-type": "application/json"}

    def __init__(self):
        self.logger = logging.getLogger("main.automower")
        self.session = requests.Session()
        self.device_id = None
        self.token = None
        self.provider = None

    def login(self, login, password):
        response = self.session.post(self._API_IM + "token",
                                     headers=self._HEADERS,
                                     json={
                                         "data": {
                                             "attributes": {
                                                 "password": password,
                                                 "username": login
                                             },
                                             "type": "token"
                                         }
                                     })

        response.raise_for_status()
        self.logger.info("Logged in successfully")

        response_json = response.json()
        self.set_token(response_json["data"]["id"], response_json["data"]["attributes"]["provider"])
        return response_json["data"]["attributes"]["expires_in"]

    def logout(self):
        response = self.session.delete(self._API_IM + f"token/{self.token}")
        response.raise_for_status()
        self.device_id = None
        self.token = None
        del (self.session.headers["Authorization"])
        self.logger.info("Logged out successfully")

    def set_token(self, token, provider):
        self.token = token
        self.provider = provider
        self.session.headers.update({
            "Authorization": "Bearer " + self.token,
            "Authorization-Provider": provider
        })

    def list_robots(self):
        response = self.session.get(self._API_APP + "mowers", headers=self._HEADERS)
        response.raise_for_status()

        return response.json()

    def select_robot(self, mower):
        result = self.list_robots()
        if not len(result):
            raise CommandException("No mower found")
        if mower:
            for item in result:
                if item["name"] == mower or item["id"] == mower:
                    self.device_id = item["id"]
                    break
            if self.device_id is None:
                raise CommandException(f"Could not find a mower matching {mower}")
        else:
            self.device_id = result[0]["id"]

    def status(self):
        response = self.session.get(self._API_APP + f"mowers/{self.device_id}/status", headers=self._HEADERS)
        response.raise_for_status()

        return response.json()

    def geo_status(self):
        response = self.session.get(self._API_APP + f"mowers/{self.device_id}/geofence", headers=self._HEADERS)
        response.raise_for_status()

        return response.json()

    def control(self, command, param=None):
        if command in ["PARK", "PARK_DURATION_PERIOD", "PARK_DURATION_TIMER", "START", "START_OVERRIDE_PERIOD", "STOP"]:
            command_url = command.replace("__", "-").replace("_", "/").lower()
            response = self.session.post(self._API_APP + f"mowers/{self.device_id}/control/{command_url}",
                                         headers=self._HEADERS,
                                         json=param)
        else:
            raise CommandException("Unknown command")

        response.raise_for_status()


def as_json(**kwargs):
    from json import dumps
    print(dumps(kwargs, indent=2))


_errors = []


def log_error(args, msg):
    if args.json:
        _errors.append(str(msg))
    else:
        logger.error(msg)


def create_config(args):
    config = AutoMowerConfig()
    config.load_config()
    if args.login:
        config.login = args.login
    if args.password:
        config.password = args.password
    if args.log_level:
        config.log_level = args.log_level
    if hasattr(args, "expire_status") and args.expire_status:
        config.expire_status = args.expire_status
    token_config = TokenConfig()
    token_config.load_config()

    if (not args.token or not token_config.token_valid()) and (not config.login or not config.password):
        log_error(args, "Missing login or password")
        return None, None

    if args.save:
        if config.save_config():
            logger.info("Configuration saved in \"automower.cfg\"")
        else:
            logger.info("Failed to saved configuration in \"automower.cfg\"")

    return config, token_config


def configure_log(config):
    logger.setLevel(logging.INFO)
    if config.log_level == "ERROR":
        logger.setLevel(logging.ERROR)

    steam_handler = logging.StreamHandler()
    logger.addHandler(steam_handler)

    logger.info("Logger configured")


def setup_api(config, token_config, args):
    mow = API()
    if args.token and token_config.token and not token_config.token_valid():
        logger.warning(f"The token expired on {token_config.expire_on}. Will create a new one.")
    if args.token and token_config.token_valid():
        mow.set_token(token_config.token, token_config.provider)
    else:
        expire = mow.login(config.login, config.password)
        if args.token:
            token_config.token = mow.token
            token_config.provider = mow.provider
            token_config.expire_on = datetime.now() + timedelta(0, expire)
            token_config.save_config()
            logger.info("Updated token")
    mow.select_robot(args.mower)
    return mow


def run_cli(config, token_config, args):
    retry = 3
    mow = None
    if args.json:
        def out(res):
            as_json(**{args.command: res})
    else:
        pp = pprint.PrettyPrinter(indent=2)
        out = pp.pprint
    while retry > 0:
        try:
            mow = setup_api(config, token_config, args)
            if args.command == "control":
                if args.action in ["PARK_DURATION_PERIOD", "START_OVERRIDE_PERIOD"]:
                    mow.control(args.action, {"period": args.period})
                else:
                    mow.control(args.action)
            elif args.command == "status":
                out(mow.status())
            elif args.command == "list":
                out(mow.list_robots())

            retry = 0
        except CommandException as ce:
            log_error(args, f"[ERROR] Wrong parameters: {ce}")
            break
        except Exception as ex:
            retry -= 1
            if retry > 0:
                log_error(args, f"[ERROR] {ex}. Retrying to send the command {3 - retry}")
            else:
                log_error(args, "[ERROR] Failed to send the command")
                break

    logger.info("Done")

    if mow is not None and not args.token:
        mow.logout()


class HTTPRequestHandler(BaseHTTPRequestHandler):
    config = None
    tokenConfig = None
    args = None
    last_status = ""
    last_status_check = 0

    def do_GET(self):
        logger.info("Try to execute " + self.path)

        # use cache for status command
        if self.path == "/status":
            # XXX where do we store status properly ? Class variables are not thread safe...
            if HTTPRequestHandler.last_status_check > time.time() - HTTPRequestHandler.config.expire_status:
                logger.info("Get status from cache")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(HTTPRequestHandler.last_status).encode("ascii"))
                return

        retry = 3
        fatal = False
        mow = None
        while retry > 0:
            try:
                mow = setup_api(HTTPRequestHandler.config, HTTPRequestHandler.tokenConfig, HTTPRequestHandler.args)

                if self.path == "/start":
                    mow.control("START")
                    self.send_response(200)
                    self.end_headers()
                elif self.path.startswith("/start/override/period/"):
                    mow.control("START_OVERRIDE_PERIOD", {"period": int(self.path[23:])})
                    self.send_response(200)
                    self.end_headers()
                elif self.path == "/stop":
                    mow.control("STOP")
                    self.send_response(200)
                    self.end_headers()
                elif self.path == "/park":
                    mow.control("PARK")
                    self.send_response(200)
                    self.end_headers()
                elif self.path.startswith("/park/duration/period/"):
                    mow.control("PARK_DURATION_PERIOD", {"period": int(self.path[22:])})
                    self.send_response(200)
                    self.end_headers()
                elif self.path == "/park/duration/timer":
                    mow.control("PARK_DURATION_TIMER")
                    self.send_response(200)
                    self.end_headers()
                elif self.path == "/status":
                    logger.info("Get status from Husqvarna servers")
                    HTTPRequestHandler.last_status = mow.status()
                    HTTPRequestHandler.last_status_check = time.time()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(HTTPRequestHandler.last_status).encode("ascii"))
                else:
                    self.send_response(400)
                    self.end_headers()

                retry = 0
            except CommandException as ce:
                msg = f"[ERROR] Wrong parameters: {ce}"
                logger.error(msg)
                self.send_response(500, msg)
                fatal = True
                break
            except Exception as ex:
                retry -= 1
                if retry > 0:
                    logger.error(ex)
                    logger.error(f"[ERROR] Retrying to send the command {retry}")
                else:
                    logger.error("[ERROR] Failed to send the command")
                    self.send_response(500)

            logger.info("Done")

            if mow is not None and not HTTPRequestHandler.args.token:
                mow.logout()
            if fatal:
                exit(1)


def run_server(config, token_config, args):
    server_address = (args.address, args.port)
    HTTPRequestHandler.config = config
    HTTPRequestHandler.tokenConfig = token_config
    HTTPRequestHandler.args = args
    httpd = HTTPServer(server_address, HTTPRequestHandler)
    httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Speak with your automower",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(dest="command")
    ask_password = argparse.Namespace()

    parser_control = subparsers.add_parser("control", help="Send command to your automower")
    parser_control.add_argument("action", choices=["STOP", "START", "START_OVERRIDE_PERIOD", "PARK",
                                                    "PARK_DURATION_PERIOD", "PARK_DURATION_TIMER"],
                                help="the command")
    parser_control.add_argument("--period", dest="period", type=int,
                               help="Minutes for override period")

    parser_list = subparsers.add_parser("list", help="List all the mowers connected to the account.")
    parser_status = subparsers.add_parser("status", help="Get the status of your automower")

    parser_server = subparsers.add_parser("server", help="Run an http server to handle commands")
    parser_server.add_argument("--address", dest="address", default="127.0.0.1",
                               help="IP address for server")
    parser_server.add_argument("--port", dest="port", type=int, default=1234,
                               help="port for server")
    parser_server.add_argument("--expire", dest="expire_status", type=int, default=30,
                               help="Status needs to be refreshed after this time")

    parser.add_argument("--login", dest="login", help="Your login")
    parser.add_argument("--password", dest="password", nargs="?", const=ask_password,
                        help="Your password. If used without arguments it will prompt")
    parser.add_argument("--save", dest="save", action="store_true",
                        help="Save command line information in automower.cfg. NOTE: the passwords is saved in cleartext")
    parser.add_argument("--no-token", dest="token", action="store_false",
                        help="Disabled the use of the token")
    parser.add_argument("--logout", dest="logout", action="store_true",
                        help="Logout an existing token saved in token.cfg")
    parser.add_argument("--mower", dest="mower",
                        help="Select the mower to use. It can be the name or the id of the mower. If not provided the first mower will be used.")
    parser.add_argument("--log-level", dest="log_level", choices=["INFO", "ERROR"],
                        help="Display all logs or just in case of error")
    parser.add_argument("--json", action="store_true",
                        help="Enable json output. Logger will be set to \"ERROR\"")

    args = parser.parse_args()
    if args.password == ask_password:
        import getpass
        args.password = getpass.getpass()

    if args.json:
        args.log_level = "ERROR"

    config, token_config = create_config(args)
    if not config:
        if args.json:
            as_json(errors=_errors)
        else:
            parser.print_help()
        exit(1)

    configure_log(config)

    if args.logout and token_config.token_valid():
        mow = API()
        mow.set_token(token_config.token, token_config.provider)
        mow.logout()
        token_config = TokenConfig()
        token_config.save_config()
    elif args.command == "server":
        run_server(config, token_config, args)
    else:
        run_cli(config, token_config, args)
        if args.json and _errors:
            as_json(errors=_errors)

    exit(0)
