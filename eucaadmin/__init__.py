

class EucaBaseObj(object):
    # Base Class For Eucalyptus Admin Query Objects
    def __init__(self, connection=None):
        self.connection = connection
        self.name = None

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.name)

    def startElement(self, name, value, connection):
        pass

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            setattr(self, ename.lower(), value)


class EucaEmpyreanResponse(EucaBaseObj):
    """
    Used to parse Base Empyrean response
    Mainly used to sort out the Empyrean message for return code/status, and to
    gather information from the status message during failures.
    """
    @property
    def statusmessages(self):
        if self._statusmessages:
            return self._statusmessages.messages
        else:
            return None

    @property
    def eucareturn(self):
        if self.empyreanmessage:
            return self.empyreanmessage._return
        else:
            return None

    def startElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'statusmessages':
                self._statusmessages = EucaStatusMessages(connection=connection)
                return self._statusmessages
            if ename == 'empyreanmessage':
                self.empyreanmessage = EucaEmpyreanMessage(connection=connection)
                return self.empyreanmessage


class EucaEmpyreanMessage(EucaBaseObj):
    """
    Common Empyrean response fields
    '_return' is often used to represent the 'status/exit/return code'
    """

    def __init__(self, connection=None):
        self.statusmessages = ""
        self._return = None
        self._services = None
        self._disabledservices = None
        self._notreadyservices = None
        self._stoppedservices = None
        super(EucaEmpyreanMessage, self).__init__(connection)


class EucaStatusMessages(EucaBaseObj):
    """
    Upon failures this field may contain information, errors, etc..
    """

    def __init__(self, connection=None):
        self._message_entries = []
        super(EucaStatusMessages, self).__init__(connection)

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.messages)

    @property
    def messages(self):
        return "\n".join(str(x.value) for x in self._message_entries)

    def startElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename == 'item':
            message_entry = EucaMessageEntry(connection=connection)
            self._message_entries.append(message_entry)
            return message_entry


class EucaMessageEntry(EucaBaseObj):
    '''
    Used to parse the actual status message from the entry field
    '''

    def __init__(self, connection=None):
        self.value = None
        super(EucaMessageEntry, self).__init__(connection)

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.value)

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'entry':
                self.value = value
            else:
                setattr(self, ename.lower(), value)


class EucaResponseException(Exception):

    def __init__(self, value, respobj=None):
        """
        Can be used to handle failed euca empyrean requests, the response can be returned
        in the exception and may provide value in case of parse errors, debugging etc..
        """
        self.value = str(value)
        self.respobj = respobj

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class EucaNotFoundException(Exception):

    def __init__(self, errmsg, notfounddict):
        """
        To be used when an administrative lookup can not find an item.
        ie: a particular service, or property is not found
        :params: errmsg: string, errmsg to be used
        :params: notfounddict: dict of items not found. Usually where the key is the name
                 of the arg provided, ie:'arg name' : 'value'
        """

        self.errmsg = errmsg
        self.notfounddict = notfounddict or {}

    @property
    def value(self):
        notfounddict = self.notfounddict or {}
        if not isinstance(notfounddict, dict):
            searchitems = {}
        return '{0}. ({1})'.format(
            self.errmsg,
            ", ".join('{0}="{1}"'.format(key, value) for key, value in notfounddict.iteritems()))

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)
