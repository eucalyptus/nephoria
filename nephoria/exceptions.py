
class EucaAdminRequired(Exception):
    """
    Used when an operation which requires eucalyptus/admin access is attempted by a user
    which does not have the ability to execute.
    """
    def __init__(self, value=None):
        self.value = value or 'Eucalyptus administrative account required to perform ' \
                              'this operation'

    def __str__(self):
        return repr(self.value)

class EucaSysAdminRequired(Exception):
    """
    Used when an operation which requires machine login user access is attempted by a user
    which does not have the ability to execute.
    """
    def __init__(self, value=None):
        self.value = value or 'System administrative access required to perform ' \
                              'this operation'

    def __str__(self):
        return repr(self.value)
