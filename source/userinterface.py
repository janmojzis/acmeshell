#based on UserInterface from Solamyl

import readline, os, sys

class UserInterface:
    """
    Handles typical user interface tasks.
    """

    def __init__(self, config):
        """
        Initialize object and pre-set user interface behaviour.
        """

        self.flagexit = False
        self.exitcode = 1

        # remember config options
        self.config = config

        # input from stdin?
        if os.isatty(sys.stdin.fileno()):
                self.config["stdin"] = "tty"
        else:
                self.config["stdin"] = "file"


        # if defined "HOME" environment variable
        self.histfile = ""
        if config["histfile"]:
                if "HOME" in os.environ:
                        # read history file
                        self.histfile = config["histfile"]
                        try:
                                readline.read_history_file(self.histfile)
                        except IOError:
                                pass  # ignore read error

        #add methods
        self.methods = []
        for method in dir(self):
            if (method[0:7] == "method_"):
                self.methods.append(method[7:])


    def _completeMethodName(self, text, state):
        """
        The completer function is called as function(text, state),
        for state in 0, 1, 2, ..., until it returns a non-string value.
        It should return the next possible completion starting with text.
        return (str or None) Method name alternative or None on end.
        param text (str) Method name prefix.
        param state (int) Requested alternative number.
        """
        i = 0  # array index
        num = 0  # number of matching entries
        txtlen = len(text)  # length of the prefix
        while i < len(self.methods):
            if self.methods[i][:txtlen] == text:
                # matching name
                if num >= state:
                    # found
                    return self.methods[i]
                # count valid entry
                num = num + 1
            # next array index
            i = i + 1
        # no more matching names
        return None

    def readCommand(self):
        """
        Read whole command from stdin.
        return (str) Input command stored into string..
        """

        # read lines until end
        text = ""
        num = 0
        while 1:
            # prepare prompt string
            if self.config["stdin"] == "tty":
                # terminal input
                if num == 0:
                    prompt = self.config["name"] + "> "  # first line
                else:
                    prompt = "> "  # next lines
            else:
                # input from file (no prompt)
                prompt = ""

            # read single line
            try:
                if int(sys.version[0]) >= 3:
                    line = input(prompt)
                else:
                    line = raw_input(prompt)
                if num == 0:
                    text = line  # first line
                else:
                    text = text + "\n" + line  # next lines
            except KeyboardInterrupt:
                # interrupted by ctrl + c
                if self.config["stdin"] == "tty":
                    # terminate broken line
                    print("")
                    if len(text) > 0 or len(readline.get_line_buffer()) > 0:
                        # abort reading command
                        return ""
                # quit UI
                return None
            except:
                # error--ignore previous input
                if self.config["stdin"] == "tty":
                    print("")  # produce linefeed
                return None
            #increment line count
            num = num + 1

            return text

    def method_exit(self, arg):
        """
        Internal method:
        Exits user interface.
        """

        self.flagexit = True

    def printdoc(self, func):
        """
        Function formats string from __doc__
        and prints it. 
        """
        
        text = func.__doc__
        if not text:
                print("help for method '%s' not exist" % arg)

        for line in text.split('\n'):
                print(line.strip())

    def method_help(self, arg):
        """
        Internal method:
        Adds help for methods.
        """

        arg = arg.strip()

        if arg:
                try:
                        func = getattr(self, "method_%s" % arg)
                except AttributeError:
                        raise Exception("method '%s' not exist" % arg)
                else:
                        self.printdoc(func)
        else:
                self.printdoc(self)

    def handle(self, func, arg, cmd):
        """
        Override this function to handle exceptions, logs, ...
        """

        func(arg)

    def serve(self):
        """
        Wait for input, read and parse commands,
        execute actions and display results.
        """
        # set completer function
        readline.set_completer(self._completeMethodName)
        # bind complete() function to tab
        readline.parse_and_bind("tab: complete")

        # forever loop
        while not self.flagexit:
            # read command
            cmd = self.readCommand()
            if cmd is None:
                break  # exit

            if cmd.find(" ") >= 0:
                cmd, arg = cmd.split(" ", 1)
                arg = arg.lstrip()
            else:
                arg = ""
            cmd = cmd.lower()

            if not len(cmd):
                    continue
            
            try:
                func = getattr(self, "method_%s" % cmd)
            except AttributeError:
                print("method '%s' unimplemented" % (cmd))
            else:
                self.handle(func, arg, cmd)
                #func(arg)

        # save history only for terminal input
        if self.histfile and self.config["stdin"] == "tty":
            # write history file
            readline.write_history_file(self.histfile)
        return self.exitcode
