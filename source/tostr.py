def tostr(x):
        """
        python2/3 compatible conversion to str from str/bytes
        """
        if isinstance(x, str):
                return x
        if isinstance(x, bytes):
                r = ""
                if len(x) > 0 and isinstance(x[0], int):
                        for ch in x: r += chr(ch)
                else:
                        for ch in x: r += ch
                return r
        raise TypeError("tostr() accepts only <type 'str'> or <class 'bytes'> not %s" % (type(x)))
