import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from smda.SmdaConfig import SmdaConfig

config = SmdaConfig()
config.API_COLLECTION_FILES = {"winxp": config.PROJECT_ROOT + os.sep + "data" + os.sep + "apiscout_winxp_prof_sp3.json"}
