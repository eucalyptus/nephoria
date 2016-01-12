# Copyright 2011-2014 Eucalyptus Systems, Inc.
#
# Redistribution and use of this software in source and binary forms,
# with or without modification, are permitted provided that the following
# conditions are met:
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from nephoria.testconnection import TestConnection
import boto
from boto.ec2.regioninfo import RegionInfo
from boto.sts import STSConnection


class STSops(TestConnection):
    AWS_REGION_SERVICE_PREFIX = 'ec2'
    EUCARC_URL_NAME = 'sts_url'
    CONNECTION_CLASS = STSConnection

    def get_session_token( self, duration=None ):
        """
        Get a possibly cached session token, if getting a new token request the given duration
        Options:
            duration - The desired duration for the token in seconds (if issued, None for default duration)
        """
        return self.connection.get_session_token( duration )

    def issue_session_token( self, duration=None ):
        """
        Get a newly issued session token with the given (or default) duration
        Options:
            duration - The desired duration for the token in seconds (None for default duration)
        """
        return self.connection.get_session_token( duration, force_new=True )

