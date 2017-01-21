import inspect
import operator
import signal
import time


class TimeoutFunctionException(Exception):
    """Exception to raise on a timeout"""
    pass

class TimeoutError(Exception):
    def __init__(self, message, elapsed=None, *args, **kwargs):
        self.elapsed = elapsed
        super(TimeoutError, self).__init__(message, *args, **kwargs)


class TimerSeconds:
    def __init__(self, time=1, timeout_message=None):
        self.time = time or 1
        self.message = timeout_message
        self.start_time = None
        self.elapsed = None
    def handle_timeout(self, signum, frame):
        if self.start_time is not None:
            self.elapsed = time.time() - self.start_time
        message  = self.message or 'TimeOut fired after "{0}/{1}" seconds!'\
            .format(self.elapsed, self.time)
        raise TimeoutError(message, elapsed=self.elapsed)
    def __enter__(self):
        self.start_time = time.time()
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.time)
    def __exit__(self, type, value, traceback):
        if self.start_time is not None:
            self.elapsed = time.time() - self.start_time
        signal.alarm(0)


class WaitForResultException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def wait_for_result(callback,
                    result,
                    timeout=60,
                    poll_wait=10,
                    oper=operator.eq,
                    allowed_exception_types=None,
                    debug_method=None,
                    **callback_kwargs):
    """
        Repeatedly run and wait for the provided callback to return the expected result,
        or timeout

        :param callback: A function/method to run and monitor the result of
        :param result: result from the call back provided that we are looking for
        :param poll_wait:Time to wait between callback executions
        :param timeout: Time in seconds to wait before timing out and returning failure
        :param allowed_exception_types: list of exception classes that can be caught and allow
                                        the wait_for_result operation to continue
        :param oper: operator obj used to evaluate 'result' against callback's
                     result. ie operator.eq, operator.ne, etc..
        :param debug_method: optional method to use when writing debug messages
        :param callback_kwargs: optional kwargs to be provided to 'callback' when its executed
        :return: result upon success
        :raise: TimeoutFunctionException when instance does not enter proper state
        """
    if not debug_method:
        try:
            # Naughty/lazy way to log results using the caller's logger interface
            caller = inspect.currentframe().f_back.f_locals['self']
            logger = getattr(caller, 'logger', None)
            if logger:
                debug_method = logger.debug
        except Exception as E:
            pass
    debug = debug_method
    if not debug:
        def debug(msg):
            print str(msg)
    allowed_exception_types = allowed_exception_types or []
    debug("Beginning poll loop for result " + str(callback.func_name) + " to go to " +
          str(result))
    start = time.time()
    elapsed = 0
    current_state = callback(**callback_kwargs)
    elapsed = int(time.time() - start)
    while (elapsed < timeout and not oper(current_state, result)):
        debug(str(callback.func_name) + ' returned: "' + str(current_state) + '" after ' +
              str(elapsed / 60) + " minutes " + str(elapsed % 60) + " seconds.")
        debug("Sleeping for " + str(poll_wait) + " seconds")
        time.sleep(poll_wait)
        try:
            current_state = callback(**callback_kwargs)
        except allowed_exception_types as AE:
            debug('Caught allowed exception:' + str(AE))
            pass
        elapsed = int(time.time() - start)
    debug(str(callback.func_name) + ' returned: "' + str(current_state) + '" after ' +
          str(elapsed / 60) + " minutes " + str(elapsed % 60) + " seconds.")
    if not oper(current_state, result):
        raise TimeoutFunctionException(str(callback.func_name) + " did not return " +
                                       str(operator.ne.__name__) +
                                       "(" + str(result) + ") true after elapsed:" + str(elapsed))
    return current_state
