# resettimer.py
#
# (c) 2018 Marco Starke
#


import threading


class ResetTimer(threading.Thread):
    # found at
    # https://code.activestate.com/recipes/577407-resettable-timer-class-a-little-enhancement-from-p/
    """
    Call a function after a specified number of seconds:

    t = ResetTimer(10, f, args = None, kwargs = None)
    t.start()
    t.reset(interval = 20) # reset the timer with new interval
    t.cancel() # stop the timer's action if it's still waiting

    Parameters:

    interval          wait 'interval' seconds until function is called
    synchronization   for multiprocessing purposes a shared Event object must be provided (managed)
    functions         function which should be called after 'interval' seconds
    """

    def __init__(self, interval, synchronization, function, args=None, kwargs=None):
        threading.Thread.__init__(self)
        self.interval = interval * 1.0 if interval else None  # ensure floating point
        self.function = function
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self.finished = synchronization  # threading.Event()
        self.finished.clear()  # initial clear
        self.resetted = True

    def cancel(self):
        """Stop the timer if it hasn't finished yet."""
        self.finished.set()

    def run(self):
        while self.resetted:
            self.resetted = False
            timeout = not self.finished.wait(self.interval)

        if not self.finished.is_set() and timeout:  # only call if timeout REALLY happened
            self.function(*self.args, **self.kwargs)

        self.finished.set()

    def reset(self, interval=None):
        if interval:
            self.interval = interval

        self.resetted = True
        self.finished.set()
        self.finished.clear()
