import os, sys
try:
        import cPickle as pickle
except ImportError:
        import pickle

def subprocessrun(func, *args, **kwds):
        """
        python2/3 compatible function for runing functions in separate process
        """
        fromchild, tochild = os.pipe()
        pid = os.fork()
        if (pid == 0):
                #child
                os.close(fromchild)
                try:
                        r = func(*args, **kwds)
                        status = 0
                except Exception as e:
                        status = 111
                        r = e
                with os.fdopen(tochild, 'wb') as f:
                        try:
                                pickle.dump(r, f, pickle.HIGHEST_PROTOCOL)
                        except pickle.PicklingError as e:
                                status = 111
                                pickle.dump(e, f, pickle.HIGHEST_PROTOCOL)
                        pickle.dump(r, f, pickle.HIGHEST_PROTOCOL)
                sys.exit(status)
        #parent
        os.close(tochild)
        with os.fdopen(fromchild, 'rb') as f:
                try:
                        result = pickle.load(f)
                except EOFError as e:
                        result = None

        #wait for child
        (_pid, status) = os.waitpid(pid, 0)

        #success
        if status == 0: return result

        #failure - function in subprocess raised an exception
        if result: raise result

        #failure - process killed or exited with status > 0
        st = os.WEXITSTATUS(status)
        if os.WTERMSIG(status) > 0:
                raise Exception("subprocess was killed by signal %d" % (os.WTERMSIG(status)))
        else:
                raise Exception("subprocess exited with status %d" % (os.WEXITSTATUS(status)))
