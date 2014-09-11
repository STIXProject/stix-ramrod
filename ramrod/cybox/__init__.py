
TAG_CYBOX_MAJOR  = "cybox_major_version"
TAG_CYBOX_MINOR  = "cybox_minor_version"
TAG_CYBOX_UPDATE = "cybox_update_version"

CYBOX_VERSIONS = ('2.0', '2.0.1', '2.1')


from update import (CYBOX_2_0_Updater, CYBOX_2_0_1_Updater, CYBOX_2_1_Updater)
CYBOX_UPDATERS = {
    '2.0': CYBOX_2_0_Updater,
    '2.0.1': CYBOX_2_0_1_Updater,
    '2.1': CYBOX_2_1_Updater
}