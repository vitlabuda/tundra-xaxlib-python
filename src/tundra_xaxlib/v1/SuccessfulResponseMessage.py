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


from __future__ import annotations
from typing import Union
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from .WireformattableIface import WireformattableIface
from .MessageType import MessageType
from ._ValidationHelpers import _ValidationHelpers
from ._WireformatHelpers import _WireformatHelpers
from ..exc.InvalidWireformatMessageDataExc import InvalidWireformatMessageDataExc


__all__ = "SuccessfulResponseMessage",


@dataclass(frozen=True)
class SuccessfulResponseMessage(WireformattableIface):
    message_type: MessageType
    cache_lifetime: int
    message_identifier: int
    source_ip_address: Union[IPv4Address, IPv6Address]
    destination_ip_address: Union[IPv4Address, IPv6Address]

    def __post_init__(self):
        """
        :raises InvalidMessageDataExc
        """

        _ValidationHelpers.validate_cache_lifetime(cache_lifetime=self.cache_lifetime)

        _ValidationHelpers.validate_message_identifier(message_identifier=self.message_identifier)

        _ValidationHelpers.validate_ip_address_versions_for_message_type(
            message_type=self.message_type,
            source_ip_address=self.source_ip_address,
            destination_ip_address=self.destination_ip_address,
            expected_4to6_ip_version=IPv6Address,
            expected_6to4_ip_version=IPv4Address
        )

    @classmethod
    def from_wireformat(cls, wireformat_bytes: bytes) -> SuccessfulResponseMessage:  # DP: Factory
        """
        :raises InvalidMessageDataExc
        """

        parsed_wireformat = _WireformatHelpers.from_wireformat(
            wireformat_bytes=wireformat_bytes,
            expected_4to6_ip_version=IPv6Address,
            expected_6to4_ip_version=IPv4Address
        )

        assert ((parsed_wireformat.source_ip_address is not None) and (parsed_wireformat.destination_ip_address is not None))

        if (not parsed_wireformat.response_bit) or parsed_wireformat.error_bit or parsed_wireformat.icmp_bit:
            raise InvalidWireformatMessageDataExc("In case of a successful response message, 'response_bit' must be set, whereas 'error_bit' and 'icmp_bit' must be unset!")

        return cls(
            message_type=parsed_wireformat.message_type,
            cache_lifetime=parsed_wireformat.cache_lifetime,
            message_identifier=parsed_wireformat.message_identifier,
            source_ip_address=parsed_wireformat.source_ip_address,
            destination_ip_address=parsed_wireformat.destination_ip_address
        )

    def to_wireformat(self) -> bytes:
        return _WireformatHelpers.to_wireformat(
            response_bit=True,
            error_bit=False,
            icmp_bit=False,
            message_type=self.message_type,
            cache_lifetime=self.cache_lifetime,
            message_identifier=self.message_identifier,
            source_ip_address=self.source_ip_address,
            destination_ip_address=self.destination_ip_address
        )
