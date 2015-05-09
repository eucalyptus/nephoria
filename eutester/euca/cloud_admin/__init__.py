
__author__ = 'clarkmatthew'

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
         ename = name.lower().replace('euca:','')
         if ename:
            setattr(self, ename.lower(), value)


class EucaEmpyreanResponse(EucaBaseObj):

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
    def __init__(self, connection=None):
        self.statusmessages = ""
        self._return = None
        self._services = None
        self._disabledservices = None
        self._notreadyservices = None
        self._stoppedservices = None
        super(EucaEmpyreanMessage, self).__init__(connection)


class EucaStatusMessages(EucaBaseObj):
    def __init__(self, connection=None):
        self._message_entries = []
        super(EucaStatusMessages, self).__init__(connection)

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.messages)

    @property
    def messages(self):
        return "\n".join(str(x.value) for x in self._message_entries)

    def startElement(self, name, value, connection):
        ename = name.lower().replace('euca:','')
        if ename == 'item':
            message_entry = EucaMessageEntry(connection=connection)
            self._message_entries.append(message_entry)
            return message_entry

class EucaMessageEntry(EucaBaseObj):
    def __init__(self, connection=None):
        self.value = None
        super(EucaMessageEntry, self).__init__(connection)

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.value)

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:','')
        if ename:
            if ename == 'entry':
                self.value = value
            else:
                setattr(self, ename.lower(), value)

class EucaResponseException(Exception):

    def __init__(self, value, respobj=None):
        self.value = str(value)
        self.respobj = respobj

    def __str__(self):
        return str("{0}:{1}".format(self.__class__.__name__, self.value))

    def __repr__(self):
        return str("{0}:{1}".format(self.__class__.__name__, self.value))
