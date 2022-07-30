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
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
import struct
from .MessageType import MessageType
from .V1Constants import V1Constants
from ._InternalV1Constants import _InternalV1Constants
from ._MiscHelpers import _MiscHelpers
from ._ValidationHelpers import _ValidationHelpers
from ..TundraXaxlibConstants import TundraXaxlibConstants
from ..etc.UninstantiableClassMixin import UninstantiableClassMixin
from ..exc.InvalidWireformatMessageDataExc import InvalidWireformatMessageDataExc


# This is not really a class as per OOP definition, but rather a collection of semi-independent functions.
class _WireformatHelpers(UninstantiableClassMixin):
    @dataclass(frozen=True)
    class ParsedWireformat:
        response_bit: bool
        error_bit: bool
        icmp_bit: bool
        message_type: MessageType
        cache_lifetime: int
        message_identifier: int
        source_ip_address: Optional[Union[IPv4Address, IPv6Address]]
        destination_ip_address: Optional[Union[IPv4Address, IPv6Address]]

    @classmethod
    def from_wireformat(cls, wireformat_bytes: bytes, expected_4to6_ip_version: Optional[Union[Type[IPv4Address], Type[IPv6Address]]], expected_6to4_ip_version: Optional[Union[Type[IPv4Address], Type[IPv6Address]]]) -> ParsedWireformat:
        """
        :raises InvalidMessageDataExc
        """

        _ValidationHelpers.validate_wireformat_size(wireformat_bytes)

        first_8_bytes = wireformat_bytes[0:8]
        source_ip_address_bytes = wireformat_bytes[8:24]
        destination_ip_address_bytes = wireformat_bytes[24:40]

        magic_byte, protocol_version, message_type_byte, cache_lifetime, message_identifier = struct.unpack("!cBBBI", first_8_bytes)

        if magic_byte != TundraXaxlibConstants.MAGIC_BYTE:
            raise InvalidWireformatMessageDataExc(f"'magic_byte' must be {TundraXaxlibConstants.MAGIC_BYTE}, got {magic_byte}!")
        if protocol_version != V1Constants.PROTOCOL_VERSION:
            raise InvalidWireformatMessageDataExc(f"'protocol_version' must be {V1Constants.PROTOCOL_VERSION}, got {protocol_version}!")

        response_bit, error_bit, icmp_bit, message_type = cls._convert_message_type_byte_to_bits_and_message_type(message_type_byte)

        ip_version = _MiscHelpers.get_expected_ip_version_for_message_type(
            message_type=message_type,
            expected_4to6_ip_version=expected_4to6_ip_version,
            expected_6to4_ip_version=expected_6to4_ip_version
        )

        source_ip_address = cls._convert_16_bytes_to_optional_ip_address_object(source_ip_address_bytes, ip_version)
        destination_ip_address = cls._convert_16_bytes_to_optional_ip_address_object(destination_ip_address_bytes, ip_version)

        return cls.ParsedWireformat(
            response_bit=response_bit,
            error_bit=error_bit,
            icmp_bit=icmp_bit,
            message_type=message_type,
            cache_lifetime=cache_lifetime,
            message_identifier=message_identifier,
            source_ip_address=source_ip_address,
            destination_ip_address=destination_ip_address
        )

    @staticmethod
    def _convert_message_type_byte_to_bits_and_message_type(message_type_byte: int) -> tuple[bool, bool, bool, MessageType]:
        """
        :raises InvalidMessageDataExc
        """

        response_bit = bool(message_type_byte & _InternalV1Constants.BITMASK_RESPONSE_BIT)
        error_bit = bool(message_type_byte & _InternalV1Constants.BITMASK_ERROR_BIT)
        icmp_bit = bool(message_type_byte & _InternalV1Constants.BITMASK_ICMP_BIT)

        message_type_int = (message_type_byte & _InternalV1Constants.BITMASK_MESSAGE_TYPE_INT)
        try:
            message_type = ({member.value: member for member in MessageType})[message_type_int]
        except KeyError:
            raise InvalidWireformatMessageDataExc(f"'message_type' must be of one of these values: {repr(tuple(member.value for member in MessageType))}, got {message_type_int}!")

        return response_bit, error_bit, icmp_bit, message_type

    @staticmethod
    def _convert_16_bytes_to_optional_ip_address_object(ip_address_bytes: bytes, ip_version: Optional[Union[Type[IPv4Address], Type[IPv6Address]]]) -> Optional[Union[IPv4Address, IPv6Address]]:
        """
        :raises InvalidMessageDataExc
        """

        assert (len(ip_address_bytes) == 16)

        if isinstance(ip_version, type):  # issubclass() does not accept 'None' (or any other instance which is not a class) as its first argument
            if issubclass(ip_version, IPv4Address):
                if ip_address_bytes[4:] != (b'\x00' * 12):
                    raise InvalidWireformatMessageDataExc("'source_ip_address' or 'destination_ip_address' should be carrying an IPv4 address, but the field's last 12 bytes are nonzero!")
                return IPv4Address(ip_address_bytes[0:4])

            if issubclass(ip_version, IPv6Address):
                return IPv6Address(ip_address_bytes)

        return None

    @classmethod
    def to_wireformat(cls, response_bit: bool, error_bit: bool, icmp_bit: bool,
                      message_type: MessageType, cache_lifetime: int, message_identifier: int,
                      source_ip_address: Optional[Union[IPv4Address, IPv6Address]],
                      destination_ip_address: Optional[Union[IPv4Address, IPv6Address]]) -> bytes:

        message_type_byte = cls._convert_bits_and_message_type_to_message_type_byte(response_bit, error_bit, icmp_bit, message_type)
        first_8_bytes = struct.pack("!cBBBI",
                                    TundraXaxlibConstants.MAGIC_BYTE,
                                    V1Constants.PROTOCOL_VERSION,
                                    message_type_byte,
                                    cache_lifetime,
                                    message_identifier
                                    )

        source_ip_address_bytes = cls._convert_optional_ip_address_object_to_16_bytes(source_ip_address)
        destination_ip_address_bytes = cls._convert_optional_ip_address_object_to_16_bytes(destination_ip_address)

        result = (first_8_bytes + source_ip_address_bytes + destination_ip_address_bytes)
        assert (len(result) == V1Constants.WIREFORMAT_MESSAGE_SIZE)
        return result

    @staticmethod
    def _convert_bits_and_message_type_to_message_type_byte(response_bit: bool, error_bit: bool, icmp_bit: bool, message_type: MessageType) -> int:
        message_type_byte = message_type.value
        if response_bit:
            message_type_byte |= _InternalV1Constants.BITMASK_RESPONSE_BIT
        if error_bit:
            message_type_byte |= _InternalV1Constants.BITMASK_ERROR_BIT
        if icmp_bit:
            message_type_byte |= _InternalV1Constants.BITMASK_ICMP_BIT

        return message_type_byte

    @staticmethod
    def _convert_optional_ip_address_object_to_16_bytes(ip_address_object: Optional[Union[IPv4Address, IPv6Address]]) -> bytes:
        if ip_address_object is None:
            return b'\x00' * 16

        return (ip_address_object.packed + (b'\x00' * 12))[0:16]
