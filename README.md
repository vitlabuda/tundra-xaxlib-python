<!--
Copyright (c) 2022 Vít Labuda. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:
 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
    disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
    following disclaimer in the documentation and/or other materials provided with the distribution.
 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
    products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-->

# tundra-xaxlib-python
`tundra-xaxlib-python`, or **Tundra-NAT64 external address translation library for Python**, enables one to easily 
parse and constructs wireformat messages used by _Tundra-NAT64 external address translation protocol_
([specification](https://github.com/vitlabuda/tundra-nat64/blob/main/external_addr_xlat/EXTERNAL-ADDR-XLAT-PROTOCOL.md))
in Python programs. Although this library will probably be most commonly used to implement servers, it is also
able to construct request messages and parse response messages, which are actions that only the client, i.e.
[Tundra-NAT64](https://github.com/vitlabuda/tundra-nat64), needs to perform.



## Installation
**Coming soon!**



## Usage
Classes and variables try to reflect the 
[protocol specification](https://github.com/vitlabuda/tundra-nat64/blob/main/external_addr_xlat/EXTERNAL-ADDR-XLAT-PROTOCOL.md)
as closely as possible in terms of both names and functionality, so I would recommend to start there.

This library's central (data)classes are [RequestMessage](src/tundra_xaxlib/v1/RequestMessage.py),
[SuccessfulResponseMessage](src/tundra_xaxlib/v1/SuccessfulResponseMessage.py) and
[ErroneousResponseMessage](src/tundra_xaxlib/v1/ErroneousResponseMessage.py). Each of them can be instantiated the 
usual way, or by using the `from_wireformat()` classmethod for parsing wireformat. The instances then have the 
`to_wireformat()` method for constructing wireformat. The [RequestMessage](src/tundra_xaxlib/v1/RequestMessage.py)
class has additional methods for constructing response message objects which use existing data from the request:
`generate_successful_response()` and `generate_erroneous_response()`. Methods which have it documented in their 
docstrings raise [InvalidMessageDataExc](src/tundra_xaxlib/exc/InvalidMessageDataExc.py) (or a subclass thereof) in 
case an error occurs. If you, for some reason, needed to detect the appropriate message class from wireformat or 
instantiate it straightaway, the [WireformatParsingHelpers](src/tundra_xaxlib/v1/WireformatParsingHelpers.py) class 
is there to help with that.



## Examples
- **[001_nat64.py](examples/001_nat64.py)** – An example external address translation server which works almost exactly 
  the same as [Tundra-NAT64](https://github.com/vitlabuda/tundra-nat64)'s built-in `nat64` addressing mode, i.e. it is 
  able to, without the help of a NAT66, statelessly translate packets from one source IPv6 to one source IPv4 and do 
  the inverse process for packets going the other way.



## Licensing
This project is licensed under the **3-clause BSD license** – see the [LICENSE](LICENSE) file.

Programmed by **[Vít Labuda](https://vitlabuda.cz/)**.
