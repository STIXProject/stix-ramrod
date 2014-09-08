from .update import (STIX_VERSIONS, STIX_1_0_Updater, STIX_1_0_1_Updater,
                     STIX_1_1_Updater)

STIX_UPDATERS = {'1.0': STIX_1_0_Updater,
                 '1.0.1': STIX_1_0_1_Updater,
                 '1.1': STIX_1_1_Updater}