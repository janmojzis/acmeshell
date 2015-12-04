import os

def savesync(fn, data):
        """
        """

        f = open(fn, 'wb')
        f.write(data)
        os.fsync(f.fileno())
        f.close()
