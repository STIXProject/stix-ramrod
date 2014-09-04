
# Example Usage

import ramrod
from ramrod import UpdateError

try:
    ramrod.update('doc.xml')
except UpdateError as ex:
    for node in ex.disallowed:
        print node.tag, node.sourceline


ramrod.update('doc.xml', force=True)

