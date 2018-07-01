#!/usr/bin/python

import os
import json

import logging
LOGGER = logging.getLogger(__name__)


class ApiResolver(object):
    """ Minimal WinAPI reference resolver, extracted from ApiScout """

    def __init__(self, db_filepath):
        self.has_64bit = False
        self.api_map = {}
        self._loadDbFile(db_filepath)

    def _loadDbFile(self, db_filepath):
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
                self.has_64bit |= bitness == 64
                base_address = api_db["dlls"][dll_entry]["base_address"]
                virtual_address = base_address + export["address"]
                api_map[virtual_address] = (dll_name, api_name)
        LOGGER.info("loaded %d exports from %d DLLs (%s).", num_apis_loaded, len(api_db["dlls"]), api_db["os_name"])
        self.api_map = api_map

    def resolveApiByAddress(self, absolute_addr):
        api_entry = ("", "")
        if absolute_addr in self.api_map:
            api_entry = self.api_map[absolute_addr]
        return api_entry
