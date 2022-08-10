#!/usr/bin/python3

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


#######################################################################################################################
# This example external address translation server works almost exactly the same as Tundra-NAT64's built-in 'nat64'
# addressing mode, i.e. it is able to, without the help of a NAT66, statelessly translate packets from one source IPv6
# to one source IPv4 and do the inverse process for packets going the other way.
#
# This asyncio-based server implements all the transports Tundra can work with, i.e. 'inherited-fds', 'unix' and 'tcp',
# and makes use of the 'tundra-xaxlib-python' library to parse and construct request and response messages.
#
# Please note that this server may seem overcomplicated partly due to it supporting all the three transports. When
# implementing your own server, you certainly do not have to support all of them, since the 'tundra-xaxlib-python'
# library is completely transport-agnostic. This server passes client connections to the 'handle_client()' function,
# and the 'handle_client_request()' function deals with clients' requests.
#######################################################################################################################


from typing import final, Final, Union, Sequence
import dataclasses
import os
import sys
import socket
import signal
import datetime
import ipaddress
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "../src"))
from tundra_xaxlib.v1.V1Constants import V1Constants
from tundra_xaxlib.v1.MessageType import MessageType
from tundra_xaxlib.v1.RequestMessage import RequestMessage
from tundra_xaxlib.exc.InvalidMessageDataExc import InvalidMessageDataExc


@final
class Settings:
    # --- General ---
    PRINT_DEBUG_MESSAGES: Final[bool] = True
    CAUGHT_SIGNALS: Final[frozenset[int]] = frozenset({signal.SIGTERM, signal.SIGINT, signal.SIGHUP})

    # --- Translation ---
    NAT64_IPV4: Final[ipaddress.IPv4Address] = ipaddress.IPv4Address("192.168.64.2")
    NAT64_IPV6: Final[ipaddress.IPv6Address] = ipaddress.IPv6Address("fd64::2")
    NAT64_PREFIX: Final[ipaddress.IPv6Network] = ipaddress.IPv6Network("64:ff9b::/96")
    ALLOW_TRANSLATION_OF_PRIVATE_IPS: Final[bool] = True
    CACHE_LIFETIME: Final[int] = 5

    # --- Transport ---
    TRANSPORT: Final[str] = "unix"
    UNIX_LISTEN_PATH: Final[str] = "/tmp/tundra-external.sock"

    # TRANSPORT: Final[str] = "tcp"
    TCP_LISTEN_HOST: Final[str] = "127.0.0.1"
    TCP_LISTEN_PORT: Final[int] = 6446

    # TRANSPORT: Final[str] = "inherited-fds"
    INHERITED_FDS_TRANSLATOR_THREADS: Final[int] = 8
    INHERITED_FDS_TUNDRA_EXECUTABLE_PATH: Final[str] = "/root/tundra_test/tundra-nat64.elf"
    INHERITED_FDS_TUNDRA_CONFIGURATION: Final[str] = f"""
        program.translator_threads = {INHERITED_FDS_TRANSLATOR_THREADS}
        program.chroot_dir =
        program.privilege_drop_user =
        program.privilege_drop_group =
    
        io.mode = tun
        io.tun.device_path =
        io.tun.interface_name = tundra
        io.tun.owner_user =
        io.tun.owner_group =
    
        router.ipv4 = 192.168.64.1
        router.ipv6 = fd64::1
        router.generated_packet_ttl = 224
    
        addressing.mode = external
        addressing.external.cache_size.main_addresses = 1000
        addressing.external.cache_size.icmp_error_addresses = 10
        addressing.external.transport = inherited-fds
    
        translator.ipv4.outbound_mtu = 1500
        translator.ipv6.outbound_mtu = 1500
        translator.6to4.copy_dscp_and_ecn = yes
        translator.4to6.copy_dscp_and_ecn = yes
    
        !STOP
    """
    # All the commands will be supplied with the above Tundra-NAT64 configuration via stdin.
    INHERITED_FDS_RUN_COMMANDS_BEFORE_STARTING_TUNDRA: Final[tuple[str, ...]] = (
        f"{INHERITED_FDS_TUNDRA_EXECUTABLE_PATH} --config-file=- mktun",
        "ip link set dev tundra up",
        "ip addr add 192.168.64.254/24 dev tundra",
        "ip addr add fd64::fffe/64 dev tundra",
        "ip route add 64:ff9b::/96 dev tundra",
        "ip6tables -t nat -A POSTROUTING -d 64:ff9b::/96 -o tundra -j SNAT --to-source=fd64::2",
        "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
    )
    INHERITED_FDS_RUN_COMMANDS_AFTER_STOPPING_TUNDRA: Final[tuple[str, ...]] = (
        "ip6tables -t nat -D POSTROUTING -d 64:ff9b::/96 -o tundra -j SNAT --to-source=fd64::2",
        "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        "ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        f"{INHERITED_FDS_TUNDRA_EXECUTABLE_PATH} --config-file=- rmtun",
    )


class ThisShouldNeverHappenExc(RuntimeError):
    def __init__(self, error_message: str):
        RuntimeError.__init__(self, error_message)


class CommandFailedExc(Exception):
    def __init__(self, command: str, exit_code: int):
        Exception.__init__(self, f"The command {repr(command)} failed! (exit code: {exit_code})")


class AddressTranslationFailedExc(Exception):
    def __init__(self, icmp_bit: bool):
        Exception.__init__(self, "Address translation failed!")

        self._icmp_bit: Final[bool] = icmp_bit

    @property
    def icmp_bit(self) -> bool:
        return self._icmp_bit


def print_with_banner(banner: str, *args) -> None:
    print(f'[{banner.upper()} {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]', *args)


def print_warn(*args) -> None:
    print_with_banner("WARN", *args)


def print_info(*args) -> None:
    print_with_banner("INFO", *args)


def print_debug(*args) -> None:
    if Settings.PRINT_DEBUG_MESSAGES:
        print_with_banner("DEBUG", *args)


def check_if_ip_address_is_usable(ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> None:
    if ip_address.is_unspecified or ip_address.is_loopback or ip_address.is_multicast:
        raise AddressTranslationFailedExc(icmp_bit=False)

    if isinstance(ip_address, ipaddress.IPv4Address):
        packed_ip_address = ip_address.packed
        if (packed_ip_address[0] == b'\x00') or (packed_ip_address == b'\xff\xff\xff\xff'):
            raise AddressTranslationFailedExc(icmp_bit=False)


def check_if_ip_address_is_not_private_if_needed(ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> None:
    if (not Settings.ALLOW_TRANSLATION_OF_PRIVATE_IPS) and ip_address.is_private:
        # Tundra-NAT64's built-in 'nat64' addressing mode does not send ICMP messages in case an address is private;
        #  however, it is requested there so the functionality is tested this way.
        # Due to the 'icmp_bit' being set to 'True' here, this function must not be called if the message type is not
        #  '*_MAIN_PACKET'!
        raise AddressTranslationFailedExc(icmp_bit=True)


def perform_prefix_4to6_translation(ipv4_address: ipaddress.IPv4Address) -> ipaddress.IPv6Address:
    return ipaddress.IPv6Address(Settings.NAT64_PREFIX.network_address.packed[0:12] + ipv4_address.packed)


def perform_prefix_6to4_translation(ipv4_in_nat64_prefix: ipaddress.IPv6Address) -> ipaddress.IPv4Address:
    if ipv4_in_nat64_prefix in Settings.NAT64_PREFIX:
        return ipaddress.IPv4Address(ipv4_in_nat64_prefix.packed[12:])

    raise AddressTranslationFailedExc(icmp_bit=False)


def perform_translator_ip_4to6_translation(ipv4_address: ipaddress.IPv4Address) -> ipaddress.IPv6Address:
    if ipv4_address == Settings.NAT64_IPV4:
        return Settings.NAT64_IPV6

    raise AddressTranslationFailedExc(icmp_bit=False)


def perform_translator_ip_6to4_translation(ipv6_address: ipaddress.IPv6Address) -> ipaddress.IPv4Address:
    if ipv6_address == Settings.NAT64_IPV6:
        return Settings.NAT64_IPV4

    raise AddressTranslationFailedExc(icmp_bit=False)


def perform_address_translation(message_type: MessageType, source_ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], destination_ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    if message_type == MessageType.MT_4TO6_MAIN_PACKET:
        check_if_ip_address_is_usable(source_ip_address)
        check_if_ip_address_is_usable(destination_ip_address)
        check_if_ip_address_is_not_private_if_needed(source_ip_address)
        check_if_ip_address_is_not_private_if_needed(destination_ip_address)
        return perform_prefix_4to6_translation(source_ip_address), perform_translator_ip_4to6_translation(destination_ip_address)

    if message_type == MessageType.MT_4TO6_ICMP_ERROR_PACKET:
        return perform_translator_ip_4to6_translation(source_ip_address), perform_prefix_4to6_translation(destination_ip_address)

    if message_type == MessageType.MT_6TO4_MAIN_PACKET:
        check_if_ip_address_is_usable(source_ip_address)
        check_if_ip_address_is_usable(destination_ip_address)
        check_if_ip_address_is_not_private_if_needed(source_ip_address)
        check_if_ip_address_is_not_private_if_needed(destination_ip_address)
        return perform_translator_ip_6to4_translation(source_ip_address), perform_prefix_6to4_translation(destination_ip_address)

    if message_type == MessageType.MT_6TO4_ICMP_ERROR_PACKET:
        return perform_prefix_6to4_translation(source_ip_address), perform_translator_ip_6to4_translation(destination_ip_address)

    raise ThisShouldNeverHappenExc(f"Invalid message type: {message_type}")


async def handle_client_request(stream_reader: asyncio.streams.StreamReader, stream_writer: asyncio.streams.StreamWriter) -> None:
    request_message = RequestMessage.from_wireformat(await stream_reader.readexactly(V1Constants.WIREFORMAT_MESSAGE_SIZE))

    try:
        translated_source_ip_address, translated_destination_ip_address = perform_address_translation(
            message_type=request_message.message_type,
            source_ip_address=request_message.source_ip_address,
            destination_ip_address=request_message.destination_ip_address
        )
    except AddressTranslationFailedExc as e:
        response_message = request_message.generate_erroneous_response(icmp_bit=e.icmp_bit)
        print_debug(f"Translation ERROR - {request_message.message_type.name}; ('{request_message.source_ip_address}', '{request_message.destination_ip_address}')")
    else:
        response_message = request_message.generate_successful_response(
            cache_lifetime=Settings.CACHE_LIFETIME,
            source_ip_address=translated_source_ip_address,
            destination_ip_address=translated_destination_ip_address
        )
        print_debug(f"Translation SUCCESS - {request_message.message_type.name}; ('{request_message.source_ip_address}', '{request_message.destination_ip_address}') => ('{response_message.source_ip_address}', '{response_message.destination_ip_address}')")

    stream_writer.write(response_message.to_wireformat())
    await stream_writer.drain()


async def handle_client(stream_reader: asyncio.streams.StreamReader, stream_writer: asyncio.streams.StreamWriter) -> None:
    printable_peer_name = repr(stream_writer.get_extra_info('peername'))

    print_debug(f"A new client has connected - {printable_peer_name}")
    try:
        while True:
            await handle_client_request(stream_reader, stream_writer)
    except (OSError, EOFError):
        pass
    except InvalidMessageDataExc as e:
        print_warn(f"An invalid message has been received (from {printable_peer_name}): {str(e)}")
    finally:
        try:
            stream_writer.close()
            await stream_writer.wait_closed()
        except (OSError, EOFError):
            pass
        print_debug(f"A client has disconnected - {printable_peer_name}")


async def execute_command_sequence(command_sequence: Sequence[str]) -> None:
    for command in command_sequence:
        process = await asyncio.subprocess.create_subprocess_shell(
            cmd=command,
            stdin=asyncio.subprocess.PIPE
        )

        process.stdin.write(Settings.INHERITED_FDS_TUNDRA_CONFIGURATION.encode("utf-8"))
        await process.stdin.drain()

        exit_code = await process.wait()
        if exit_code != 0:
            raise CommandFailedExc(command, exit_code)


async def unix_main(signal_caught_event: asyncio.Event) -> None:
    print_info("Starting Unix socket server...")
    server = await asyncio.start_unix_server(
        client_connected_cb=handle_client,
        path=Settings.UNIX_LISTEN_PATH
    )

    print_info(f"Unix socket server is listening on {repr(Settings.UNIX_LISTEN_PATH)}...")
    await signal_caught_event.wait()

    print_info("Stopping Unix socket server...")
    server.close()
    await server.wait_closed()


async def tcp_main(signal_caught_event: asyncio.Event) -> None:
    print_info("Starting TCP server...")
    server = await asyncio.start_server(
        client_connected_cb=handle_client,
        host=Settings.TCP_LISTEN_HOST,
        port=Settings.TCP_LISTEN_PORT,
        reuse_address=True,
        reuse_port=False,
        start_serving=True
    )

    print_info(f"TCP server is listening on {repr([sock.getsockname() for sock in server.sockets])}...")
    await signal_caught_event.wait()

    print_info("Stopping TCP server...")
    server.close()
    await server.wait_closed()


async def inherited_fds_main(signal_caught_event: asyncio.Event) -> None:
    @dataclasses.dataclass(frozen=True)
    class _TranslatorThreadData:
        stream_reader: asyncio.streams.StreamReader
        stream_writer: asyncio.streams.StreamWriter
        tundra_socket: socket.socket
        task: asyncio.Task

    print_info("Running commands before starting Tundra...")
    await execute_command_sequence(Settings.INHERITED_FDS_RUN_COMMANDS_BEFORE_STARTING_TUNDRA)

    print_info("Opening communication channels & coroutines...")
    translator_thread_data_objects = []
    for _ in range(Settings.INHERITED_FDS_TRANSLATOR_THREADS):
        my_socket, tundra_socket = socket.socketpair(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
        stream_reader, stream_writer = await asyncio.open_unix_connection(sock=my_socket)
        task = asyncio.create_task(handle_client(stream_reader, stream_writer))
        translator_thread_data_objects.append(_TranslatorThreadData(stream_reader, stream_writer, tundra_socket, task))

    print_info("Starting Tundra-NAT64...")
    inherited_fds_string = ";".join("{fd},{fd}".format(fd=thread_data.tundra_socket.fileno()) for thread_data in translator_thread_data_objects)
    tundra_process = await asyncio.subprocess.create_subprocess_exec(
        Settings.INHERITED_FDS_TUNDRA_EXECUTABLE_PATH, "--config-file=-", f"--addressing-external-inherited-fds={inherited_fds_string}", "translate",
        pass_fds=tuple(thread_data.tundra_socket.fileno() for thread_data in translator_thread_data_objects),
        stdin=asyncio.subprocess.PIPE
    )

    print_info("Sending configuration to Tundra-NAT64...")
    tundra_process.stdin.write(Settings.INHERITED_FDS_TUNDRA_CONFIGURATION.encode("utf-8"))
    await tundra_process.stdin.drain()

    print_info("Waiting for a signal to be caught...")
    await signal_caught_event.wait()

    print_info("Stopping Tundra-NAT64...")
    tundra_process.send_signal(signal.SIGTERM)
    await tundra_process.wait()

    print_info("Closing communication channels & coroutines...")
    for thread_data in translator_thread_data_objects:
        thread_data.task.cancel()
        try:
            await thread_data.task
        except asyncio.CancelledError:
            pass
        thread_data.tundra_socket.close()
        thread_data.stream_writer.close()
        await thread_data.stream_writer.wait_closed()

    print_info("Running commands after stopping Tundra...")
    await execute_command_sequence(Settings.INHERITED_FDS_RUN_COMMANDS_AFTER_STOPPING_TUNDRA)


def generate_signal_caught_asyncio_event() -> asyncio.Event:
    event = asyncio.Event()

    def _signal_handler():
        print_warn("A signal has been caught!")
        event.set()

    for signum in Settings.CAUGHT_SIGNALS:
        asyncio.get_event_loop().add_signal_handler(signum, _signal_handler)

    return event


async def main() -> None:
    assert (Settings.NAT64_PREFIX.prefixlen == 96)

    print_info("Initializing...")

    signal_caught_event = generate_signal_caught_asyncio_event()

    try:
        transport_handler = ({
            "unix": unix_main,
            "tcp": tcp_main,
            "inherited-fds": inherited_fds_main
        }[Settings.TRANSPORT])
    except KeyError:
        raise ThisShouldNeverHappenExc(f"Invalid value of 'Settings.TRANSPORT': {repr(Settings.TRANSPORT)}")

    await transport_handler(signal_caught_event)

    print_info("Done!")


if __name__ == '__main__':
    asyncio.run(main())
