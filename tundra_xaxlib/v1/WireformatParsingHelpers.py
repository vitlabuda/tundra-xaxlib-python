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
from .RequestMessage import RequestMessage
from .SuccessfulResponseMessage import SuccessfulResponseMessage
from .ErroneousResponseMessage import ErroneousResponseMessage
from ._InternalV1Constants import _InternalV1Constants
from ._ValidationHelpers import _ValidationHelpers
from ..etc.UninstantiableClassMixin import UninstantiableClassMixin


__all__ = "WireformatParsingHelpers",


# This is not really a class as per OOP definition, but rather a collection of semi-independent functions.
class WireformatParsingHelpers(UninstantiableClassMixin):
    @classmethod
    def instantiate_appropriate_message_class_from_wireformat(cls, wireformat_bytes: bytes) -> Union[RequestMessage, SuccessfulResponseMessage, ErroneousResponseMessage]:  # DP: Factory
        """
        :raises InvalidMessageDataExc
        """

        return cls.detect_message_class_from_wireformat(wireformat_bytes).from_wireformat(wireformat_bytes)

    # Keep in mind that this method performs absolutely minimal validation (it is done this way so parts of code are
    #  not unnecessarily repeated) - the fact that this function successfully returns a message class does not mean
    #  that calling 'from_wireformat()' on it will not fail!
    @staticmethod
    def detect_message_class_from_wireformat(wireformat_bytes: bytes) -> Union[Type[RequestMessage], Type[SuccessfulResponseMessage], Type[ErroneousResponseMessage]]:
        """
        :raises InvalidMessageDataExc
        """

        _ValidationHelpers.validate_wireformat_size(wireformat_bytes)

        message_type_byte = int(wireformat_bytes[2])

        if message_type_byte & _InternalV1Constants.BITMASK_RESPONSE_BIT:  # = If 'response_bit' is set
            if message_type_byte & _InternalV1Constants.BITMASK_ERROR_BIT:  # = If both 'response_bit' and 'error_bit' are set
                return ErroneousResponseMessage
            return SuccessfulResponseMessage

        return RequestMessage
