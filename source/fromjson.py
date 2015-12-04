import json

def fromjson(x):
        """
        python2/3 compatible conversion from json string
        """
        return json.loads(x)
