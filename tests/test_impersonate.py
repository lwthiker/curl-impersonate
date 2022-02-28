import os
import io
import logging
import subprocess

import yaml
import dpkt
import pytest

from signature import BrowserSignature, TLSClientHelloSignature


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
        sig = BrowserSignature(
            tls_client_hello=TLSClientHelloSignature.from_bytes(
                self.CLIENT_HELLO
            )
        )

        sig2 = BrowserSignature.from_dict(
            browser_signatures["chrome_98.0.4758.102_win10"]["signature"]
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

    @pytest.fixture
    def tcpdump(self):
        """Initialize a sniffer to capture curl's traffic."""
        logging.debug(
            f"Running tcpdump on interface {self.TCPDUMP_CAPTURE_INTERFACE}"
        )

        p = subprocess.Popen([
            "tcpdump", "-n",
            "-i", self.TCPDUMP_CAPTURE_INTERFACE,
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

    def _extract_client_hello(self, pcap: bytes) -> bytes:
        """Find and return the Client Hello TLS record from a pcap.

        If there are multiple, returns the first.
        If there are none, returns None.
        """
        for ts, buf in dpkt.pcap.Reader(io.BytesIO(pcap)):
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
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

    @pytest.mark.parametrize(
        "curl_binary, env_vars, expected_signature",
        [
            # Test wrapper scripts
            ("chrome/curl_chrome98", None, "chrome_98.0.4758.102_win10"),
            ("chrome/curl_edge98", None, "edge_98.0.1108.62_win10"),
            ("firefox/curl_ff91esr", None, "firefox_91.6.0esr_win10"),
            ("firefox/curl_ff95", None, "firefox_95.0.2_win10"),

            # Test libcurl-impersonate by loading it with LD_PRELOAD to an app
            # linked against the regular libcurl and setting the
            # CURL_IMPERSONATE env var.
            (
                "./minicurl",
                {
                    "LD_PRELOAD": "./chrome/libcurl-impersonate.so",
                    "CURL_IMPERSONATE": "chrome98"
                },
                "chrome_98.0.4758.102_win10"
            ),
            (
                "./minicurl",
                {
                    "LD_PRELOAD": "./chrome/libcurl-impersonate.so",
                    "CURL_IMPERSONATE": "edge98"
                },
                "edge_98.0.1108.62_win10"
            ),
            (
                "./minicurl",
                {
                    "LD_PRELOAD": "./firefox/libcurl-impersonate.so",
                    "CURL_IMPERSONATE": "ff91esr"
                },
                "firefox_91.6.0esr_win10"
            ),
            (
                "./minicurl",
                {
                    "LD_PRELOAD": "./firefox/libcurl-impersonate.so",
                    "CURL_IMPERSONATE": "ff95"
                },
                "firefox_95.0.2_win10"
            )
        ]
    )
    def test_impersonation(self,
                           tcpdump,
                           curl_binary,
                           env_vars,
                           browser_signatures,
                           expected_signature):
        """
        Check that curl's network signature is identical to that of a
        real browser.

        Launches curl while sniffing its TLS traffic with tcpdump. Then
        extract the Client Hello packet from the capture and compares its
        signature with the expected one defined in the YAML database.
        """
        env = os.environ.copy()
        if env_vars:
            env |= env_vars

        logging.debug(f"Launching '{curl_binary}' to {self.TEST_URL}")
        if env_vars:
            logging.debug("Environment variables: {}".format(
                " ".join([f"{k}={v}" for k, v in env_vars.items()])))

        curl = subprocess.Popen([
            curl_binary,
            "-o", "/dev/null",
            "--local-port", f"{self.LOCAL_PORTS[0]}-{self.LOCAL_PORTS[1]}",
            self.TEST_URL
        ], env=env)

        ret = curl.wait(timeout=10)
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

        sig = BrowserSignature(
            tls_client_hello=TLSClientHelloSignature.from_bytes(client_hello)
        )

        expected_sig = BrowserSignature.from_dict(
            browser_signatures[expected_signature]["signature"]
        )

        equals, reason =  sig.equals(expected_sig, reason=True)
        assert equals, reason
