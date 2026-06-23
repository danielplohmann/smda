#!/usr/bin/env python
# -*- coding: utf-8 -*-

class SmdaConfig:
    # keep this in sync with smda.__version__
    VERSION = "4.1.0"
    ESCAPER_DOWNWARD_COMPATIBILITY = "1.13.16"
    CONFIG_FILE_PATH = str(os.path.abspath(__file__))
    PROJECT_ROOT = str(os.path.abspath(os.sep.join([CONFIG_FILE_PATH, "..", "..", ".."]))
