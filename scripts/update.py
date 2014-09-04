
# Example Usage

import ramrod
from ramrod import UpdateException

try:
    ramrod.update('doc.xml')
except UpdateException as ex:
    for node in ex.disallowed:
        print node.tag, node.sourceline


ramrod.update('doc.xml', force=True)

