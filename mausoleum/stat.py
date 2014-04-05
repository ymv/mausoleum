from time import time
import logging

class Timer(object):
    _all_timers = {}

    @classmethod
    def getTimer(cls, name):
        return cls._all_timers.setdefault(name, Timer())

    def __init__(self):
        self._start = {}
        self._timers = {}

    def start(self, key):
        self._start[key] = time()

    def end(self, key):
        delta = time() - self._start[key]
        total, n = self._timers.get(key, (0.0,0))
        self._timers[key] = (total + delta, n + 1)

    @classmethod
    def report(cls):
        logger = logging.getLogger('Timer')
        for name, timer in cls._all_timers.iteritems():
            for k, (total, n) in timer._timers.iteritems():
                logger.info('%s %s %d %.4f %.4f', name, k, n, total, total/n)
