
TAG_CYBOX_MAJOR  = "cybox_major_version"
TAG_CYBOX_MINOR  = "cybox_minor_version"
TAG_CYBOX_UPDATE = "cybox_update_version"

CYBOX_VERSIONS = ('2.0', '2.0.1', '2.1')

from update import (Cybox_2_0_Updater, Cybox_2_0_1_Updater, Cybox_2_1_Updater)
CYBOX_UPDATERS = {
    '2.0': Cybox_2_0_Updater,
    '2.0.1': Cybox_2_0_1_Updater,
    '2.1': Cybox_2_1_Updater
}