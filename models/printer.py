class Printer:
    """
    Singleton class.
    """
    __instance = None

    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

    def __init__(self, quiet: bool = False):
        self.__quiet: bool = quiet
        self.__state: str = "quiet" if quiet else "verbose"

    @property
    def state(self):
        return self.__state

    def set_state(self, *, quiet: bool):
        self.__quiet = quiet
        self.__state = "quiet" if quiet else "verbose"

    def __call__(self, *args, force_print: bool = False, **kwargs):
        if not self.__quiet or force_print:
            print(*args, **kwargs)
