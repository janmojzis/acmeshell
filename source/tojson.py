import json
from tobytes import tobytes

def tojson(x):
        """
        python2/3 compatible conversion to json string
        """

        return tobytes(json.dumps(x))
