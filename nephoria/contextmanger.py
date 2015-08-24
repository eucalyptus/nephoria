__author__ = 'clarkmatthew'

from nephoria.usercontext import UserContext
from inspect import isclass


#Primary test, cloud admin, system admin, and cloud user/region connection context controller


class ContextManager(object):

    def __init__(self, endpoints=None, username='root', password=None, admincreds=None,
                 testcreds=None, testaccount='testaccount1', testuser='testuser1'):
        self.current_context = None


    def get_current_ops_context(self, ops):
        """
        This method is an attempt to provide current context for cloud artifact/objects
        which may be using/referencing connections made outside the current context.
        This method attempts to allow this class to act as a sudo-context manager for
        the test connections it manages.
        """
        conn_attr = None
        # First check to see if a context is set...
        if isinstance(self.current_context, UserContext):
            # Get the attribute name of this specific ops class for the user_context obj...
            conn_attr = UserContext.CLASS_MAP.get(ops.__class__, None)
        elif isclass(ops):
            conn_attr = UserContext.CLASS_MAP.get(ops)

        if conn_attr:
            # Get the current ops/connection obj that matching the requesting ops...
            current_ops = getattr(self.current_context, conn_attr)
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


