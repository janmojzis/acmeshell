import base64
from tobytes import tobytes
from tostr import tostr

def tobase64(x):
        """
        python2/3 compatible conversion to urlsafe base64 encoding
        """

        return tostr(base64.urlsafe_b64encode(tobytes(x))).replace('=', '')
