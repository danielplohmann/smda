#!/usr/bin/python

import json
import logging
import os

import lief

lief.logging.disable()

from .AbstractLabelProvider import AbstractLabelProvider  # noqa: E402
from .import_parsers import parse_pe_delay_imports, parse_pe_imports  # noqa: E402

LOGGER = logging.getLogger(__name__)


class WinApiResolver(AbstractLabelProvider):
    """Minimal WinAPI reference resolver, extracted from ApiScout"""

    # Class-level cache: db_filepath -> (api_map, has_64bit).
    # API collection files are static on disk; parsing them once per process
    # is sufficient even when multiple WinApiResolver instances are created.
    _db_cache: dict = {}

    def __init__(self, config):
        self._config = config
        self._has_64bit = False
        self._api_map = {"lief": {}}
        self._os_name = None
        self._is_buffer = False
        for os_name, db_filepath in self._config.API_COLLECTION_FILES.items():
            self._loadDbFile(os_name, db_filepath)
        loaded_os_names = [os_name for os_name in self._config.API_COLLECTION_FILES if os_name in self._api_map]
        if len(loaded_os_names) == 1:
            self._os_name = loaded_os_names[0]

    def update(self, binary_info):
        self._is_buffer = binary_info.is_buffer
        self._api_map["lief"] = {}
        if not self._is_buffer:
            # setup import table info from LIEF
            lief_binary = binary_info.getLiefBinary()
            if not isinstance(lief_binary, lief.PE.Binary):
                return
            self._api_map["lief"] = parse_pe_imports(lief_binary, binary_info.base_addr)
            self._api_map["lief"].update(parse_pe_delay_imports(lief_binary, binary_info.base_addr))

    def setOsName(self, os_name):
        self._os_name = os_name

    def _loadDbFile(self, os_name, db_filepath):
        if db_filepath in WinApiResolver._db_cache:
            api_map, has_64bit = WinApiResolver._db_cache[db_filepath]
            self._api_map[os_name] = api_map
            self._has_64bit |= has_64bit
            LOGGER.debug("loaded %d exports from cache (%s).", len(api_map), os_name)
            return
        api_db = {}
        if os.path.isfile(db_filepath):
            with open(db_filepath, encoding="utf-8") as f_json:
                api_db = json.loads(f_json.read())
        else:
            LOGGER.error(
                'Can\'t find ApiScout collection file: "%s" -- continuing without ApiResolver.',
                db_filepath,
            )
            return
        num_apis_loaded = 0
        has_64bit = False
        api_map = {}
        for dll_entry in api_db["dlls"]:
            LOGGER.debug("  building address map for: %s", dll_entry)
            dll = api_db["dlls"][dll_entry]
            dll_name = "_".join(dll_entry.split("_")[2:])
            has_64bit |= dll["bitness"] == 64
            base_address = dll["base_address"]
            for export in dll["exports"]:
                num_apis_loaded += 1
                api_name = str(export["name"])
                if api_name == "None":
                    api_name = "None<{}>".format(export["ordinal"])
                api_map[base_address + export["address"]] = (dll_name, api_name)
        LOGGER.debug(
            "loaded %d exports from %d DLLs (%s).",
            num_apis_loaded,
            len(api_db["dlls"]),
            api_db["os_name"],
        )
        WinApiResolver._db_cache[db_filepath] = (api_map, has_64bit)
        self._api_map[os_name] = api_map
        self._has_64bit |= has_64bit

    def isApiProvider(self):
        """Returns whether the get_api(..) function of the AbstractLabelProvider is functional"""
        return True

    def getApi(self, to_addr, absolute_addr=None):
        """If the LabelProvider has any information about a used API for the given address, return (dll, api), else return (None, None)"""
        # if we work on a dump, use ApiScout method:
        if self._is_buffer:
            if self._os_name and self._os_name in self._api_map:
                return self._api_map[self._os_name].get(absolute_addr, (None, None))
            if self._os_name:
                return (None, None)
            for os_name, api_map in self._api_map.items():
                if os_name == "lief":
                    continue
                api = api_map.get(absolute_addr)
                if api:
                    return api
            return (None, None)
        # otherwise take import table info from LIEF
        else:
            return self._api_map["lief"].get(to_addr, (None, None))

    def isSymbolProvider(self):
        return False

    def getSymbol(self, address):
        return ""

    def getFunctionSymbols(self):
        return {}

    def is_active(self):
        return bool(self._is_buffer or self._api_map.get("lief"))
