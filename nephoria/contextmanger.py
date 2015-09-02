__author__ = 'clarkmatthew'

from nephoria.usercontext import UserContext
from nephoria.testconnection import TestConnection
from inspect import isclass


#Primary test, cloud admin, system admin, and cloud user/region connection context controller


class ContextManager(object):

    def __init__(self, endpoints=None, username='root', password=None, admincreds=None,
                 testcreds=None, testaccount='testaccount1', testuser='testuser1'):
        self._current_user_context = None

    def set_current_user_context(self, user_context):
        if not (user_context is None or isinstance(user_context, UserContext)):
            raise ValueError('Unsupported type for user_context: "{0}"'.format(user_context))
        self._current_user_context = user_context

    @property
    def current_user_context(self):
        return self._current_user_context

    @current_user_context.setter
    def current_user_context(self, context):
        if context is None or isinstance(context, UserContext):
            self._current_user_context = context
        else:
            raise ValueError('Uknown type for user context: "{0}"'.format(context))

    def clear_current_user_context(self):
        self.current_user_context = None

    def get_current_ops_context(self, ops):
        """
        This method is an attempt to provide current context for cloud artifact/objects
        which may be using/referencing connections made outside the current context.
        This method attempts to allow this class to act as a sudo-context manager for
        the test connections it manages.
        """
        conn_attr = None
        # First check to see if a context is set...
        if not self.current_user_context:
            return None

        if isinstance(ops, TestConnection):
            # Get the attribute name of this specific ops class for the user_context obj...
            conn_attr = UserContext.CLASS_MAP.get(ops.__class__.__name__, None)
        elif isclass(ops):
            conn_attr = UserContext.CLASS_MAP.get(ops.__name__)
        elif isinstance(ops, basestring):
            conn_attr = UserContext.CLASS_MAP.get(ops)

        if conn_attr:
            # Get the current ops/connection obj that matching the requesting ops...
            current_ops = getattr(self.current_user_context, conn_attr)
            # If this is the same ops obj, then return None so the requestor knows to use
            # it's own connection...
            if current_ops != ops:
                return current_ops
        else:
            raise ValueError('UserContext does not have Class mapping for class:"{0}"'
                             .format(ops.__class__.__name__))
        return None


    def get_connection_context(self, ops):
        """
        This method is an attempt to provide current context for cloud artifact/objects
        which may be using/referencing connections made outside the current context.
        This method attempts to allow this class to act as a sudo-context manager for
        the test connections it manages.
        """
        current_ops = self.get_current_ops_context(ops)
        if current_ops:
            # The current context differs from the obj making the request, have the
            # requesting ops obj use this connection for it's specific service instead...
            return current_ops.get_http_connection(*current_ops._connection)
        return None



