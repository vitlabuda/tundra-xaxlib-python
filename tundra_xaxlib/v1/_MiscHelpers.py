#!/bin/false

# Copyright (c) 2022 Vít Labuda. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
#     disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
#     following disclaimer in the documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
#     products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from typing import Optional, Union, Type
from ipaddress import IPv4Address, IPv6Address
from .MessageType import MessageType
from ..etc.UninstantiableClassMixin import UninstantiableClassMixin


# This is not really a class as per OOP definition, but rather a collection of independent functions.
class _MiscHelpers(UninstantiableClassMixin):
    @staticmethod
    def get_expected_ip_version_for_message_type(message_type: MessageType, expected_4to6_ip_version: Optional[Union[Type[IPv4Address], Type[IPv6Address]]], expected_6to4_ip_version: Optional[Union[Type[IPv4Address], Type[IPv6Address]]]) -> Optional[Union[Type[IPv4Address], Type[IPv6Address]]]:
        return ({
            MessageType.MT_4TO6_MAIN_PACKET: expected_4to6_ip_version,
            MessageType.MT_4TO6_ICMP_ERROR_PACKET: expected_4to6_ip_version,
            MessageType.MT_6TO4_MAIN_PACKET: expected_6to4_ip_version,
            MessageType.MT_6TO4_ICMP_ERROR_PACKET: expected_6to4_ip_version
        })[message_type]
