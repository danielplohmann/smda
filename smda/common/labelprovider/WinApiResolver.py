#!/usr/bin/python

import os
import json
import logging

from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)


class WinApiResolver(AbstractLabelProvider):
    """ Minimal WinAPI reference resolver, extracted from ApiScout """

    def __init__(self, config):
        self._config = config
        self._has_64bit = False
        self._api_map = {}
        self._os_name = None
        for os_name, db_filepath in self._config.API_COLLECTION_FILES.items():
            self._loadDbFile(os_name, db_filepath)
            self._os_name = os_name

    def update(self, binary_info):
        return

    def setOsName(self, os_name):
        self._os_name = os_name

    def _loadDbFile(self, os_name, db_filepath):
        api_db = {}
        if os.path.isfile(db_filepath):
            with open(db_filepath, "r") as f_json:
                api_db = json.loads(f_json.read())
        else:
            LOGGER.error("Can't find ApiScout collection file: \"%s\" -- continuing without ApiResolver.", db_filepath)
            return
        num_apis_loaded = 0
        api_map = {}
        for dll_entry in api_db["dlls"]:
            LOGGER.debug("  building address map for: %s", dll_entry)
            for export in api_db["dlls"][dll_entry]["exports"]:
                num_apis_loaded += 1
                api_name = "%s" % (export["name"])
                if api_name == "None":
                    api_name = "None<{}>".format(export["ordinal"])
                dll_name = "_".join(dll_entry.split("_")[2:])
                bitness = api_db["dlls"][dll_entry]["bitness"]
                self._has_64bit |= bitness == 64
                base_address = api_db["dlls"][dll_entry]["base_address"]
                virtual_address = base_address + export["address"]
                api_map[virtual_address] = (dll_name, api_name)
        LOGGER.info("loaded %d exports from %d DLLs (%s).", num_apis_loaded, len(api_db["dlls"]), api_db["os_name"])
        self._api_map[os_name] = api_map

    def isApiProvider(self):
        """Returns whether the get_api(..) function of the AbstractLabelProvider is functional"""
        return True

    def getApi(self, absolute_addr):
        """If the LabelProvider has any information about a used API for the given address, return (dll, api), else return None"""
        if self._os_name and self._os_name in self._api_map:
            return self._api_map[self._os_name].get(absolute_addr, None)
        return None
