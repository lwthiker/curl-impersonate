import os
import io
import re
import sys
import logging
import subprocess
import tempfile

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
    with open("signatures.yaml", "r") as f:
        # Parse signatures.yaml database.
        return {
            doc["name"]: doc
            for doc in yaml.safe_load_all(f.read())
            if doc
        }


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

    TEST_URL = "https://www.wikipedia.org"

    # List of binaries and their expected signatures
    CURL_BINARIES_AND_SIGNATURES = [
        # Test wrapper scripts
        ("curl_chrome98", None, None, "chrome_98.0.4758.102_win10"),
        ("curl_chrome99", None, None, "chrome_99.0.4844.51_win10"),
        ("curl_chrome99_android", None, None, "chrome_99.0.4844.73_android12-pixel6"),
        ("curl_edge98", None, None, "edge_98.0.1108.62_win10"),
        ("curl_edge99", None, None, "edge_99.0.1150.30_win10"),
        ("curl_safari15_3", None, None, "safari_15.3_macos11.6.4"),
        ("curl_ff91esr", None, None, "firefox_91.6.0esr_win10"),
        ("curl_ff95", None, None, "firefox_95.0.2_win10"),
        ("curl_ff98", None, None, "firefox_98.0_win10"),

        # Test libcurl-impersonate by loading it with LD_PRELOAD to an app
        # linked against the regular libcurl and setting the
        # CURL_IMPERSONATE env var.
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "chrome98"
            },
            "libcurl-impersonate-chrome",
            "chrome_98.0.4758.102_win10"
        ),
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
                "CURL_IMPERSONATE": "chrome99_android"
            },
            "libcurl-impersonate-chrome",
            "chrome_99.0.4844.73_android12-pixel6"
        ),
        (
            "minicurl",
            {
                "CURL_IMPERSONATE": "edge98"
            },
            "libcurl-impersonate-chrome",
            "edge_98.0.1108.62_win10"
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
                "CURL_IMPERSONATE": "safari15_3"
            },
            "libcurl-impersonate-chrome",
            "safari_15.3_macos11.6.4"
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
        )
    ]

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

    @pytest.fixture
    def nghttpd(self):
        """Initiailize an HTTP/2 server"""
        logging.debug(f"Running nghttpd on :8443")

        p = subprocess.Popen([
            "nghttpd", "-v",
            "8443", "ssl/server.key", "ssl/server.crt"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        yield p

        p.terminate()
        p.wait(timeout=10)

    def _set_ld_preload(self, env_vars, lib):
        if sys.platform.startswith("linux"):
            env_vars["LD_PRELOAD"] = lib + ".so"
        elif sys.platform.startswith("darwin"):
            env_vars["DYLD_INSERT_LIBRARIES"] = lib + ".dylib"

    def _run_curl(self, curl_binary, env_vars, extra_args, url,
                  output="/dev/null"):
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        logging.debug(f"Launching '{curl_binary}' to {url}")
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
        args.append(url)

        curl = subprocess.Popen(args, env=env)
        return curl.wait(timeout=10)

    def _extract_client_hello(self, pcap: bytes) -> bytes:
        """Find and return the Client Hello TLS record from a pcap.

        If there are multiple, returns the first.
        If there are none, returns None.
        """
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
            return tcp.data

        return None

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
                              expected_signature):
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

        ret = self._run_curl(curl_binary,
                             env_vars=env_vars,
                             extra_args=None,
                             url=self.TEST_URL)
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

        client_hello = self._extract_client_hello(pcap)
        assert client_hello is not None

        logging.debug(f"Found Client Hello, "
                      f"comparing to signature '{expected_signature}'")

        sig = TLSClientHelloSignature.from_bytes(client_hello)
        expected_sig = TLSClientHelloSignature.from_dict(
            browser_signatures[expected_signature] \
                              ["signature"] \
                              ["tls_client_hello"]
        )

        equals, msg =  sig.equals(expected_sig, reason=True)
        assert equals, msg

    @pytest.mark.parametrize(
        "curl_binary, env_vars, ld_preload, expected_signature",
        CURL_BINARIES_AND_SIGNATURES
    )
    def test_http2_headers(self,
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
                             url="https://localhost:8443")
        assert ret == 0
        try:
            output, stderr = nghttpd.communicate(timeout=2)

            # If nghttpd finished running before timeout, it's likely it failed
            # with an error.
            assert nghttpd.returncode == 0, \
                (f"nghttpd failed with error code {nghttpd.returncode}, "
                 f"stderr: {stderr}")
        except subprocess.TimeoutExpired:
            nghttpd.kill()
            output, stderr = nghttpd.communicate(timeout=3)

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
                              expected_signature):
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
                             url=self.TEST_URL,
                             output=output)
        assert ret == 0

        with open(output, "r") as f:
            assert "<!DOCTYPE html>" in f.read()
