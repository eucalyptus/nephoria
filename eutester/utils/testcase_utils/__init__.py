import operator
import time


class TimeoutFunctionException(Exception):
    """Exception to raise on a timeout"""
    pass

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
        debug = debug_method
        if not debug:
            def debug(msg):
                print str(msg)
        allowed_exception_types = allowed_exception_types or []
        debug( "Beginning poll loop for result " + str(callback.func_name) + " to go to " +
               str(result) )
        start = time.time()
        elapsed = 0
        current_state =  callback(**callback_kwargs)
        while( elapsed <  timeout and not oper(current_state,result) ):
            debug(  str(callback.func_name) + ' returned: "' + str(current_state) + '" after '
                       + str(elapsed/60) + " minutes " + str(elapsed%60) + " seconds.")
            debug("Sleeping for " + str(poll_wait) + " seconds")
            time.sleep(poll_wait)
            try:
                current_state = callback(**callback_kwargs)
            except allowed_exception_types as AE:
                debug('Caught allowed exception:' + str(AE))
                pass
            elapsed = int(time.time()- start)
        debug(  str(callback.func_name) + ' returned: "' + str(current_state) + '" after '
                    + str(elapsed/60) + " minutes " + str(elapsed%60) + " seconds.")
        if not oper(current_state,result):
            raise TimeoutFunctionException( str(callback.func_name) + " did not return " +
                             str(operator.ne.__name__) +
                             "(" + str(result) + ") true after elapsed:"+str(elapsed))
        return current_state


