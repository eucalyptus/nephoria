

import dns.resolver
import time
from cloud_admin.services.services import EucaComponentService


class EucaDnsService(EucaComponentService):

    def __init__(self, *args, **kwargs):
        self._resolver = None
        self.host = None
        super(EucaDnsService, self).__init__(*args, **kwargs)

    @property
    def resolver(self):
        if not self._resolver:
            if self.host:
                self._resolver = dns.resolver.Resolver(configure=False)
                self._resolver.nameservers = [self.host]
        return self._resolver

    @resolver.setter
    def resolver(self, value):
        self._resolver = value

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method=self.connection.get_services,
                            get_method_kwargs={'service_type': 'dns'},
                            new_service=new_service,
                            silent=silent)

    def resolve(self, name, timeout=360, poll_count=20):
        """
        Resolve hostnames against the Eucalyptus DNS service
        """
        poll_sleep = timeout/poll_count
        for _ in range(poll_count):
            try:
                self.debug_method("DNSQUERY: Resolving `{0}' against nameserver(s) {1}"
                                  .format(name, self.resolver.nameservers))
                ans = self.resolver.query(name)
                return str(ans[0])
            except dns.resolver.NXDOMAIN:
                raise RuntimeError("Unable to resolve hostname `{0}'".format(name))
            except dns.resolver.NoNameservers:
                # Note that this usually means our DNS server returned a malformed message
                pass
            finally:
                time.sleep(poll_sleep)
        raise RuntimeError("Unable to resolve hostname `{0}'".format(name))
