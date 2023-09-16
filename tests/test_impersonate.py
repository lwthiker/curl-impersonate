import os
import io
import re
import sys
import random
import asyncio
import logging
import pathlib
import subprocess
import tempfile
import itertools
from typing import List

import yaml
import dpkt
import pytest

from signature import (
    BrowserSignature,
    TLSClientHelloSignature,
    HTTP2Signature
)


@pytest.fixture
def browser_signatures():
    docs = {}
    for path in pathlib.Path("signatures").glob("**/*.yaml"):
        with open(path, "r") as f:
            # Parse signatures.yaml database.
            docs.update({
                doc["name"]: doc
                for doc in yaml.safe_load_all(f.read())
                if doc
            })
    return docs


class TestSignatureModule:
    """Test the signature.py module.

    signature.py is responsible for decoding signatures from the YAML format,
    parsing raw TLS packets, and comparing signatures.
    """

    # Client Hello record sent by Chrome 98.
    CLIENT_HELLO = (
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x06\x84\xbd\x63\xac"
        b"\xa4\x0a\x5b\xbe\x79\x7d\x14\x48\xcc\x1f\xf8\x62\x8c\x7d\xf4\xc7"
        b"\xfe\x04\xe3\x30\xb7\x56\xec\x87\x40\xf2\x63\x20\x92\x9d\x01\xc8"
        b"\x82\x3c\x92\xe1\x8a\x75\x4e\xaa\x6b\xf1\x31\xd2\xb7\x4d\x18\xc6"
        b"\xda\x3d\x31\xa6\x35\xb2\x08\xbc\x5b\x82\x2f\x97\x00\x20\x9a\x9a"
        b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
        b"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
        b"\x01\x93\xca\xca\x00\x00\x00\x00\x00\x16\x00\x14\x00\x00\x11\x77"
        b"\x77\x77\x2e\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x2e\x6f\x72\x67"
        b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08\xaa"
        b"\xaa\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00"
        b"\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f"
        b"\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x12"
        b"\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06"
        b"\x06\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29\xaa\xaa\x00\x01"
        b"\x00\x00\x1d\x00\x20\xfc\x58\xaa\x8b\xd6\x2d\x65\x9c\x58\xa2\xc9"
        b"\x0c\x5a\x6f\x69\xa5\xef\xc0\x05\xb3\xd1\xb4\x01\x9d\x61\x84\x00"
        b"\x42\x74\xc7\xa9\x43\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x07\x06"
        b"\xaa\xaa\x03\x04\x03\x03\x00\x1b\x00\x03\x02\x00\x02\x44\x69\x00"
        b"\x05\x00\x03\x02\x68\x32\xfa\xfa\x00\x01\x00\x00\x15\x00\xc6\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00"
    )

    def test_serialization(self, browser_signatures):
        """
        Test that deserializing and then serializing the YAML signatures
        produces idential results.
        """
        for browser_name, data in browser_signatures.items():
            sig = data["signature"]

            # Unserialize and serialize back.
            sig2 = BrowserSignature.from_dict(sig).to_dict()

            # Go extension by extension and check equality.
            # It could be done with a single comparison, but this way the error
            # will be more indicative.
            for i, ext in enumerate(sig["tls_client_hello"]["extensions"]):
                assert ext == sig2["tls_client_hello"]["extensions"][i], \
                       (f"Inconsistent serialization in signature "
                        f"{browser_name}: Serialized extension "
                        f"{ext['type']} differs.")

            assert sig == sig2, \
                   (f"Inconsistent serialization in signature "
                    f"{browser_name}")

    def test_tls_client_hello_parsing(self, browser_signatures):
        """
        Test the TLS Client Hello parsing code.
        """
        sig = TLSClientHelloSignature.from_bytes(self.CLIENT_HELLO)
        sig2 = TLSClientHelloSignature.from_dict(
            browser_signatures["chrome_98.0.4758.102_win10"] \
                              ["signature"] \
                              ["tls_client_hello"]
        )

        equals, reason = sig.equals(sig2, reason=True)
        assert equals == True, reason


class TestImpersonation:
    """
    Test that the network signature of curl-impersonate is identical to that of
    a real browser, by comparing with known signatures
    """

    TCPDUMP_CAPTURE_INTERFACE = "eth0"

    # When running curl use a specific range of local ports.
    # This ensures we will capture the correct traffic in tcpdump.
    LOCAL_PORTS = (50000, 50100)

    TEST_URLS = [
        "https://www.wikimedia.org",
        "https://www.wikipedia.org",
        "https://www.mozilla.org/en-US/",
        "https://www.apache.org",
        "https://www.kernel.org",
        "https://git-scm.com"
    ]

    # List of binaries and their expected signatures
    CURL_BINARIES_AND_SIGNATURES = [
        # Test wrapper scripts
        ("curl_chrome99", None, None, "chrome_99.0.4844.51_win10"),
        ("curl_chrome100", None, None, "chrome_100.0.4896.127_win10"),
        ("curl_chrome101", None, None, "chrome_101.0.4951.67_win10"),
        ("curl_chrome104", None, None, "chrome_104.0.5112.81_win10"),
        ("curl_chrome107", None, None, "chrome_107.0.5304.107_win10"),
        ("curl_chrome110", None, None, "chrome_110.0.5481.177_win10"),
        ("curl_chrome116", None, None, "chrome_116.0.5845.180_win10"),
        ("curl_chrome99_android", None, None, "chrome_99.0.4844.73_android12-pixel6"),
        ("curl_edge99", None, None, "edge_99.0.1150.30_win10"),
        ("curl_edge101", None, None, "edge_101.0.1210.47_win10"),
        ("curl_safari15_3", None, None, "safari_15.3_macos11.6.4"),
        ("curl_safari15_5", None, None, "safari_15.5_macos12.4"),
        ("curl_ff91esr", None, None, "firefox_91.6.0esr_win10"),
        ("curl_ff95", None, None, "firefox_95.0.2_win10"),
        ("curl_ff98", None, None, "firefox_98.0_win10"),
        ("curl_ff100", None, None, "firefox_100.0_win10"),
        ("curl_ff102", None, None, "firefox_102.0_win10"),
        ("curl_ff109", None, None, "firefox_109.0_win10"),
        ("curl_ff117", None, None, "firefox_117.0.1_win10"),

        # Test libcurl-impersonate by loading it with LD_PRELOAD to an app
        # linked against the regular libcurl and setting the
        # CURL_IMPERSONATE env var.
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome99"
            },
            "libcurl-impersonate-chrome",
            "chrome_99.0.4844.51_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome100"
            },
            "libcurl-impersonate-chrome",
            "chrome_100.0.4896.127_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome101"
            },
            "libcurl-impersonate-chrome",
            "chrome_101.0.4951.67_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome104"
            },
            "libcurl-impersonate-chrome",
            "chrome_104.0.5112.81_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome107"
            },
            "libcurl-impersonate-chrome",
            "chrome_107.0.5304.107_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome110"
            },
            "libcurl-impersonate-chrome",
            "chrome_110.0.5481.177_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome116"
            },
            "libcurl-impersonate-chrome",
            "chrome_116.0.5845.180_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome99_android"
            },
            "libcurl-impersonate-chrome",
            "chrome_99.0.4844.73_android12-pixel6"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "edge99"
            },
            "libcurl-impersonate-chrome",
            "edge_99.0.1150.30_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "edge101",
            },
            "libcurl-impersonate-chrome",
            "edge_101.0.1210.47_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "safari15_3"
            },
            "libcurl-impersonate-chrome",
            "safari_15.3_macos11.6.4"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "safari15_5"
            },
            "libcurl-impersonate-chrome",
            "safari_15.5_macos12.4"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff91esr"
            },
            "libcurl-impersonate-ff",
            "firefox_91.6.0esr_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff95"
            },
            "libcurl-impersonate-ff",
            "firefox_95.0.2_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff98"
            },
            "libcurl-impersonate-ff",
            "firefox_98.0_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff100"
            },
            "libcurl-impersonate-ff",
            "firefox_100.0_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff102"
            },
            "libcurl-impersonate-ff",
            "firefox_102.0_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff109"
            },
            "libcurl-impersonate-ff",
            "firefox_109.0_win10"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "ff117"
            },
            "libcurl-impersonate-ff",
            "firefox_117.0.1_win10"
        )
    ]

    @pytest.fixture
    def test_urls(self):
        # Shuffle TEST_URLS randomly
        return random.sample(self.TEST_URLS, k=len(self.TEST_URLS))

    @pytest.fixture
    def tcpdump(self, pytestconfig):
        """Initialize a sniffer to capture curl's traffic."""
        interface = pytestconfig.getoption("capture_interface")

        logging.debug(
            f"Running tcpdump on interface {interface}"
        )

        p = subprocess.Popen([
            "tcpdump", "-n",
            "-i", interface,
            "-s", "0",
            "-w", "-",
            "-U", # Important, makes tcpdump unbuffered
            (f"(tcp src portrange {self.LOCAL_PORTS[0]}-{self.LOCAL_PORTS[1]}"
             f" and tcp dst port 443) or"
             f"(tcp dst portrange {self.LOCAL_PORTS[0]}-{self.LOCAL_PORTS[1]}"
             f" and tcp src port 443)")
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        yield p

        p.terminate()
        p.wait(timeout=10)

    async def _read_proc_output(self, proc, timeout):
        """Read an async process' output until timeout is reached"""
        data = bytes()
        loop = asyncio.get_running_loop()
        start_time = loop.time()
        passed = loop.time() - start_time
        while passed < timeout:
            try:
                data += await asyncio.wait_for(
                    proc.stdout.readline(), timeout=timeout - passed
                )
            except asyncio.TimeoutError:
                pass
            passed = loop.time() - start_time
        return data

    async def _wait_nghttpd(self, proc):
        """Wait for nghttpd to start listening on its designated port"""
        data = bytes()
        while data is not None:
            data = await proc.stdout.readline()
            if not data:
                # Process terminated
                return False

            line = data.decode("utf-8").rstrip()
            if "listen 0.0.0.0:8443" in line:
                return True

        return False

    @pytest.fixture
    async def nghttpd(self):
        """Initiailize an HTTP/2 server.
        The returned object is an asyncio.subprocess.Process object,
        so async methods must be used with it.
        """
        logging.debug(f"Running nghttpd on :8443")

        # Launch nghttpd and wait for it to start listening.

        proc = await asyncio.create_subprocess_exec(
            "nghttpd", "-v",
            "8443", "ssl/server.key", "ssl/server.crt",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            # Wait up to 3 seconds for nghttpd to start.
            # Otherwise fail.
            started = await asyncio.wait_for(
                self._wait_nghttpd(proc), timeout=3
            )
            if not started:
                raise Exception("nghttpd failed to start on time")
        except asyncio.TimeoutError:
            raise Exception("nghttpd failed to start on time")

        yield proc

        proc.terminate()
        await proc.wait()

    def _set_ld_preload(self, env_vars, lib):
        if sys.platform.startswith("linux"):
            env_vars["LD_PRELOAD"] = lib + ".so"
        elif sys.platform.startswith("darwin"):
            env_vars["DYLD_INSERT_LIBRARIES"] = lib + ".dylib"

    def _run_curl(self, curl_binary, env_vars, extra_args, urls,
                  output="/dev/null"):
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        logging.debug(f"Launching '{curl_binary}' to {urls}")
        if env_vars:
            logging.debug("Environment variables: {}".format(
                " ".join([f"{k}={v}" for k, v in env_vars.items()])))

        args = [
            curl_binary,
            "-o", output,
            "--local-port", f"{self.LOCAL_PORTS[0]}-{self.LOCAL_PORTS[1]}"
        ]
        if extra_args:
            args += extra_args
        args.extend(urls)

        curl = subprocess.Popen(args, env=env)
        return curl.wait(timeout=15)

    def _extract_client_hello(self, pcap: bytes) -> List[bytes]:
        """Find and return the Client Hello TLS record from a pcap.

        If there are multiple, returns the first.
        If there are none, returns None.
        """
        client_hellos = []
        for ts, buf in dpkt.pcap.Reader(io.BytesIO(pcap)):
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            if tcp.dport != 443 or not tcp.data:
                continue
            # We hope that the record is in a single TCP packet
            # and wasn't split across multiple packets. This is usually the case.
            tls = dpkt.ssl.TLSRecord(tcp.data)
            # Check if it's a Handshake record
            if tls.type != 0x16:
                continue
            handshake = dpkt.ssl.TLSHandshake(tls.data)
            # Check if it's a Client Hello
            if handshake.type != 0x01:
                continue
            # Return the whole TLS record
            client_hellos.append(tcp.data)

        return client_hellos

    def _parse_nghttpd2_output(self, output):
        """Parse the output of nghttpd2.

        nghttpd2 in verbose mode writes out the HTTP/2
        headers that the client had sent.
        """
        lines = output.decode("utf-8").splitlines()
        stream_id = None
        for line in lines:
            m = re.search(r"recv HEADERS frame.*stream_id=(\d+)", line)
            if m:
                stream_id = m.group(1)
                break

        assert stream_id is not None, \
               "Failed to find HEADERS frame in nghttpd2 output"

        pseudo_headers = []
        headers = []
        for line in lines:
            m = re.search(rf"recv \(stream_id={stream_id}\) (.*)", line)
            if m:
                header = m.group(1)
                # If the headers starts with ":" it is a pseudo-header,
                # i.e. ":authority". In this case keep only the header name and
                # discard the value
                if header.startswith(":"):
                    m = re.match(r"(:\w+):", header)
                    if m:
                        pseudo_headers.append(m.group(1))
                else:
                    headers.append(header)

        return pseudo_headers, headers

    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload, expected_signature",
        CURL_BINARIES_AND_SIGNATURES
    )
    def test_tls_client_hello(self,
                              pytestconfig,
                              tcpdump,
                              curl_binary,
                              env_vars,
                              ld_preload,
                              browser_signatures,
                              expected_signature,
                              test_urls):
        """
        Check that curl's TLS signature is identical to that of a
        real browser.

        Launches curl while sniffing its TLS traffic with tcpdump. Then
        extracts the Client Hello packet from the capture and compares its
        signature with the expected one defined in the YAML database.
        """
        curl_binary = os.path.join(
            pytestconfig.getoption("install_dir"), "bin", curl_binary
        )
        if ld_preload:
            # Injecting libcurl-impersonate with LD_PRELOAD is supported on
            # Linux only. On Mac there is DYLD_INSERT_LIBRARIES but it
            # reuqires more work to be functional.
            if not sys.platform.startswith("linux"):
                pytest.skip()

            self._set_ld_preload(env_vars, os.path.join(
                pytestconfig.getoption("install_dir"), "lib", ld_preload
            ))

        test_urls = test_urls[0:2]
        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=None,
                             urls=test_urls)
        assert ret == 0

        try:
            pcap, stderr = tcpdump.communicate(timeout=5)

            # If tcpdump finished running before timeout, it's likely it failed
            # with an error.
            assert tcpdump.returncode == 0, \
                (f"tcpdump failed with error code {tcpdump.returncode}, "
                 f"stderr: {stderr}")
        except subprocess.TimeoutExpired:
            tcpdump.kill()
            pcap, stderr = tcpdump.communicate(timeout=3)

        assert len(pcap) > 0
        logging.debug(f"Captured pcap of length {len(pcap)} bytes")

        client_hellos = self._extract_client_hello(pcap)
        # A client hello message for each URL
        assert len(client_hellos) == len(test_urls)

        logging.debug(f"Found {len(client_hellos)} Client Hello messages, "
                      f"comparing to signature '{expected_signature}'")

        for client_hello in client_hellos:
            sig = TLSClientHelloSignature.from_bytes(client_hello)
            expected_sig = TLSClientHelloSignature.from_dict(
                browser_signatures[expected_signature] \
                                  ["signature"] \
                                  ["tls_client_hello"]
            )

            allow_tls_permutation=browser_signatures[expected_signature]    \
                                                    ["signature"]           \
                                                    .get("options", {})     \
                                                    .get("tls_permute_extensions", False)
            equals, msg = sig.equals(
                expected_sig,
                allow_tls_permutation=allow_tls_permutation,
                reason=True
            )
            assert equals, msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload, expected_signature",
        CURL_BINARIES_AND_SIGNATURES
    )
    async def test_http2_headers(self,
                                 pytestconfig,
                                 nghttpd,
                                 curl_binary,
                                 env_vars,
                                 ld_preload,
                                 browser_signatures,
                                 expected_signature):
        curl_binary = os.path.join(
            pytestconfig.getoption("install_dir"), "bin", curl_binary
        )
        if ld_preload:
            # Injecting libcurl-impersonate with LD_PRELOAD is supported on
            # Linux only. On Mac there is DYLD_INSERT_LIBRARIES but it
            # reuqires more work to be functional.
            if not sys.platform.startswith("linux"):
                pytest.skip()

            self._set_ld_preload(env_vars, os.path.join(
                pytestconfig.getoption("install_dir"), "lib", ld_preload
            ))

        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=["-k"],
                             urls=["https://localhost:8443"])
        assert ret == 0

        output = await self._read_proc_output(nghttpd, timeout=2)

        assert len(output) > 0
        pseudo_headers, headers = self._parse_nghttpd2_output(output)

        logging.debug(
            f"Received {len(pseudo_headers)} HTTP/2 pseudo-headers "
            f"and {len(headers)} HTTP/2 headers"
        )

        sig = HTTP2Signature(pseudo_headers, headers)
        expected_sig = HTTP2Signature.from_dict(
            browser_signatures[expected_signature] \
                              ["signature"] \
                              ["http2"]
        )

        equals, msg = sig.equals(expected_sig, reason=True)
        assert equals, msg

    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload, expected_signature",
        CURL_BINARIES_AND_SIGNATURES
    )
    def test_content_encoding(self,
                              pytestconfig,
                              curl_binary,
                              env_vars,
                              ld_preload,
                              expected_signature,
                              test_urls):
        """
        Ensure the output of curl-impersonate is correct, i.e. that compressed
        responses are decoded correctly.
        """
        curl_binary = os.path.join(
            pytestconfig.getoption("install_dir"), "bin", curl_binary
        )
        if ld_preload:
            # Injecting libcurl-impersonate with LD_PRELOAD is supported on
            # Linux only. On Mac there is DYLD_INSERT_LIBRARIES but it
            # reuqires more work to be functional.
            if not sys.platform.startswith("linux"):
                pytest.skip()

            self._set_ld_preload(env_vars, os.path.join(
                pytestconfig.getoption("install_dir"), "lib", ld_preload
            ))

        output = tempfile.mkstemp()[1]
        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=None,
                             urls=[test_urls[0]],
                             output=output)
        assert ret == 0

        with open(output, "r") as f:
            body = f.read()
            assert (
                "<!DOCTYPE html>" in body or
                "<html>" in body or
                "<!doctype html>" in body
            )

    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload",
        [
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "chrome101",
                    "CURL_IMPERSONATE_HEADERS": "no"
                },
                "libcurl-impersonate-chrome"
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "ff102",
                    "CURL_IMPERSONATE_HEADERS": "no"
                },
                "libcurl-impersonate-ff",
            )
        ]
    )
    async def test_no_builtin_headers(self,
                                      pytestconfig,
                                      nghttpd,
                                      curl_binary,
                                      env_vars,
                                      ld_preload):
        """
        Ensure the built-in headers of libcurl-impersonate are not added when
        the CURL_IMPERSONATE_HEADERS environment variable is set to "no".
        """
        curl_binary = os.path.join(
            pytestconfig.getoption("install_dir"), "bin", curl_binary
        )

        if not sys.platform.startswith("linux"):
            pytest.skip()

        self._set_ld_preload(env_vars, os.path.join(
            pytestconfig.getoption("install_dir"), "lib", ld_preload
        ))

        # Use some custom headers with a specific order.
        # We will test that the headers are sent in the exact given order, as
        # it is important for users to be able to control the exact headers
        # content and order.
        headers = [
            "X-Hello: World",
            "Accept: application/json",
            "X-Goodbye: World",
            "Accept-Encoding: deflate, gzip, br"
            "X-Foo: Bar",
            "User-Agent: curl-impersonate"
        ]
        header_args = list(itertools.chain(*[
            ["-H", header]
            for header in  headers
        ]))

        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=["-k"] + header_args,
                             urls=["https://localhost:8443"])
        assert ret == 0

        output = await self._read_proc_output(nghttpd, timeout=2)

        assert len(output) > 0
        _, output_headers = self._parse_nghttpd2_output(output)
        for i, header in enumerate(output_headers):
            assert header.lower() == headers[i].lower()

    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload",
        [
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "chrome101"
                },
                "libcurl-impersonate-chrome",
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "chrome101",
                    "CURL_IMPERSONATE_HEADERS": "no"
                },
                "libcurl-impersonate-chrome",
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "ff102"
                },
                "libcurl-impersonate-ff",
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "ff102",
                    "CURL_IMPERSONATE_HEADERS": "no"
                },
                "libcurl-impersonate-ff",
            )
        ]
    )
    async def test_user_agent(
        self,
        pytestconfig,
        nghttpd,
        curl_binary,
        env_vars,
        ld_preload
    ):
        """
        Ensure that any user-agent set with CURLOPT_HTTPHEADER will override
        the one set by libcurl-impersonate.
        """
        curl_binary = os.path.join(
            pytestconfig.getoption("install_dir"), "bin", curl_binary
        )

        if not sys.platform.startswith("linux"):
            pytest.skip()

        self._set_ld_preload(env_vars, os.path.join(
            pytestconfig.getoption("install_dir"), "lib", ld_preload
        ))

        user_agent = "My-User-Agent"

        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=[
                                "-k",
                                "-H",
                                f"User-Agent: {user_agent}"
                             ],
                             urls=["https://localhost:8443"])
        assert ret == 0

        output = await self._read_proc_output(nghttpd, timeout=2)

        assert len(output) > 0

        _, headers = self._parse_nghttpd2_output(output)
        assert any([
            header.lower().startswith("user-agent:") for header in headers
        ])

        for header in headers:
            if header.lower().startswith("user-agent:"):
                assert header[len("user-agent:"):].strip() == user_agent

    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload",
        [
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "chrome101"
                },
                "libcurl-impersonate-chrome",
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "chrome101",
                    "CURL_IMPERSONATE_HEADERS": "no"
                },
                "libcurl-impersonate-chrome",
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "ff102"
                },
                "libcurl-impersonate-ff",
            ),
            (
                "minicurl",
                {
                    "CURL_IMPERSONATE": "ff102",
                    "CURL_IMPERSONATE_HEADERS": "no"
                },
                "libcurl-impersonate-ff",
            )
        ]
    )
    async def test_user_agent_curlopt_useragent(
        self,
        pytestconfig,
        nghttpd,
        curl_binary,
        env_vars,
        ld_preload
    ):
        """
        Ensure that any user-agent set with CURLOPT_USERAGENT will override
        the one set by libcurl-impersonate. See:
        https://github.com/lwthiker/curl-impersonate/issues/51
        """
        curl_binary = os.path.join(
            pytestconfig.getoption("install_dir"), "bin", curl_binary
        )

        if not sys.platform.startswith("linux"):
            pytest.skip()

        self._set_ld_preload(env_vars, os.path.join(
            pytestconfig.getoption("install_dir"), "lib", ld_preload
        ))

        user_agent = "My-User-Agent"

        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=["-k", "-A", user_agent],
                             urls=["https://localhost:8443"])
        assert ret == 0

        output = await self._read_proc_output(nghttpd, timeout=2)

        assert len(output) > 0

        _, headers = self._parse_nghttpd2_output(output)
        assert any([
            header.lower().startswith("user-agent:") for header in headers
        ])

        for header in headers:
            if header.lower().startswith("user-agent:"):
                assert header[len("user-agent:"):].strip() == user_agent
