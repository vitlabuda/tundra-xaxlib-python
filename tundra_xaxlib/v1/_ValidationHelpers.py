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


from typing import Union, Type
from ipaddress import IPv4Address, IPv6Address
from .V1Constants import V1Constants
from .MessageType import MessageType
from ._MiscHelpers import _MiscHelpers
from ..etc.UninstantiableClassMixin import UninstantiableClassMixin
from ..exc.InvalidMessageDataExc import InvalidMessageDataExc
from ..exc.InvalidWireformatMessageDataExc import InvalidWireformatMessageDataExc


# This is not really a class as per OOP definition, but rather a collection of independent functions.
class _ValidationHelpers(UninstantiableClassMixin):
    @staticmethod
    def validate_wireformat_size(wireformat_bytes: bytes) -> None:
        """
        :raises InvalidMessageDataExc
        """

        wireformat_msg_len = len(wireformat_bytes)
        if wireformat_msg_len != V1Constants.WIREFORMAT_MESSAGE_SIZE:
            raise InvalidWireformatMessageDataExc(f"Wireformat messages must be exactly {V1Constants.WIREFORMAT_MESSAGE_SIZE} bytes in size, got {wireformat_msg_len} bytes!")

    @staticmethod
    def validate_icmp_bit_for_message_type(message_type: MessageType, icmp_bit: bool) -> None:
        """
        :raises InvalidMessageDataExc
        """

        if icmp_bit and (message_type not in (MessageType.MT_4TO6_MAIN_PACKET, MessageType.MT_6TO4_MAIN_PACKET)):
            raise InvalidMessageDataExc(f"'icmp_bit' may be set only for the following message types: {MessageType.MT_4TO6_MAIN_PACKET.name}, {MessageType.MT_6TO4_MAIN_PACKET.name} (got {message_type.name})")

    @staticmethod
    def validate_cache_lifetime(cache_lifetime: int) -> None:
        """
        :raises InvalidMessageDataExc
        """

        if (cache_lifetime < 0) or (cache_lifetime > 255):
            raise InvalidMessageDataExc(f"'cache_lifetime' is out of range (0 - 255): {cache_lifetime}")

    @staticmethod
    def validate_message_identifier(message_identifier: int) -> None:
        """
        :raises InvalidMessageDataExc
        """

        if (message_identifier < 0) or (message_identifier > 4_294_967_295):  # 'message_identifier' is uint32_t
            raise InvalidMessageDataExc(f"'message_identifier' is out of range (0 - 4_294_967_295): {message_identifier}")

    @staticmethod
    def validate_ip_address_versions_for_message_type(message_type: MessageType,
                                                      source_ip_address: Union[IPv4Address, IPv6Address],
                                                      destination_ip_address: Union[IPv4Address, IPv6Address],
                                                      expected_4to6_ip_version: Union[Type[IPv4Address], Type[IPv6Address]],
                                                      expected_6to4_ip_version: Union[Type[IPv4Address], Type[IPv6Address]]) -> None:
        """
        :raises InvalidMessageDataExc
        """

        ip_version = _MiscHelpers.get_expected_ip_version_for_message_type(
            message_type=message_type,
            expected_4to6_ip_version=expected_4to6_ip_version,
            expected_6to4_ip_version=expected_6to4_ip_version
        )
        assert (ip_version is not None)

        if (not isinstance(source_ip_address, ip_version)) or (not isinstance(destination_ip_address, ip_version)):
            raise InvalidMessageDataExc(f"If 'message_type' is {message_type.name}, the source & destination IP must be an {ip_version.__name__}!")
