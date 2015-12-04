def tobytes(x):
        """
        python2/3 compatible conversion to bytes from str/bytes
        """

        #python2 unicode-hack
        try:
                if isinstance(x, unicode):
                        x = str(x)
        except NameError:
                pass

        if isinstance(x, bytes):
                return x
        if isinstance(x, str):
                r = []
                for ch in x:
                        r.append(ord(ch))
                return bytes(r)
        raise TypeError("tobytes() accepts only <type 'str'> or <class 'bytes'> not %s" % (type(x)))
