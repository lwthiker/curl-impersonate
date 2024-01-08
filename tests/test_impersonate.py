import os
import sys
import random
import logging
import pathlib
import subprocess
import tempfile
import itertools
import asyncio

import yaml
import pytest
from th1.tls.parser import parse_pcap
from th1.tls.signature import TLSClientHelloSignature
from th1.http2.parser import parse_nghttpd_log
from th1.http2.signature import HTTP2Signature


@pytest.fixture
def browser_signatures():
    docs = {}
    for path in pathlib.Path("signatures").glob("**/*.yaml"):
        with open(path, "r") as f:
            # Parse signatures.yaml database.
            docs.update(
                {
                    f'{doc["browser"]["name"]}_{doc["browser"]["version"]}_{doc["browser"]["os"]}': doc
                    for doc in yaml.safe_load_all(f.read())
                    if doc
                }
            )
    return docs


"""
Test that the network signature of curl-impersonate is identical to that of
a real browser, by comparing with known signatures
"""

# When running curl use a specific range of local ports.
# This ensures we will capture the correct traffic in tcpdump.
LOCAL_PORTS = (50000, 50100)


# https://docs.github.com/en/actions/learn-github-actions/variables
logging.debug("$CI is: %s", os.getenv("CI"))
TEST_URLS = [
    "https://www.wikimedia.org",
    "https://www.wikipedia.org",
    "https://www.mozilla.org/en-US/",
    "https://www.apache.org",
    # "https://www.kernel.org",
    "https://git-scm.com",
]
# TEST_URLS = [
#     "https://tls.browserleaks.com/json",
#     "https://httpbin.org/ip",
# ]

# List of binaries and their expected signatures
CURL_BINARIES_AND_SIGNATURES = yaml.safe_load(open("./targets.yaml"))


@pytest.fixture
def test_urls():
    # Shuffle TEST_URLS randomly
    return random.sample(TEST_URLS, k=len(TEST_URLS))


@pytest.fixture
def tcpdump(pytestconfig):
    """Initialize a sniffer to capture curl's traffic."""
    interface = pytestconfig.getoption("capture_interface")

    logging.debug(f"Running tcpdump on interface {interface}")

    p = subprocess.Popen(
        [
            "tcpdump",
            "-n",
            "-i",
            interface,
            "-s",
            "0",
            "-w",
            "-",
            "-U",  # Important, makes tcpdump unbuffered
            (
                f"(tcp src portrange {LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}"
                f" and tcp dst port 443) or"
                f"(tcp dst portrange {LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}"
                f" and tcp src port 443)"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    yield p

    p.terminate()
    p.wait(timeout=10)


async def _read_proc_output(proc, timeout: int = 5):
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


async def _wait_nghttpd(proc):
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
async def nghttpd():
    """Initialize an HTTP/2 server.
    The returned object is an asyncio.subprocess.Process object,
    so async methods must be used with it.
    """
    logging.debug("Running nghttpd on :8443")

    # Launch nghttpd and wait for it to start listening.

    proc = await asyncio.create_subprocess_exec(
        "nghttpd",
        "-v",
        "8443",
        "ssl/server.key",
        "ssl/server.crt",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        # Wait up to 3 seconds for nghttpd to start.
        # Otherwise fail.
        started = await asyncio.wait_for(_wait_nghttpd(proc), timeout=3)
        if not started:
            raise Exception("nghttpd failed to start")
    except asyncio.TimeoutError:
        raise Exception("nghttpd failed to start on time")

    yield proc

    proc.terminate()
    await proc.wait()


def _set_ld_preload(env_vars, lib):
    if sys.platform.startswith("linux"):
        env_vars["LD_PRELOAD"] = lib + ".so"
    elif sys.platform.startswith("darwin"):
        env_vars["DYLD_INSERT_LIBRARIES"] = lib + ".dylib"


def _run_curl(curl_binary, env_vars, extra_args, urls, output="/dev/null"):
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    logging.debug(f"Launching '{curl_binary}' to {urls}")
    if env_vars:
        logging.debug(
            "Environment variables: {}".format(
                " ".join([f"{k}={v}" for k, v in env_vars.items()])
            )
        )

    args = [
        curl_binary,
        "-o",
        output,
        "-o",
        output,
        "--local-port",
        f"{LOCAL_PORTS[0]}-{LOCAL_PORTS[1]}",
    ]
    if extra_args:
        args += extra_args
    args.extend(urls)
    logging.debug("runing curl with: %s", " ".join(args))

    curl = subprocess.Popen(args, env=env)
    return curl.wait(timeout=15)


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, expected_signature",
    CURL_BINARIES_AND_SIGNATURES,
)
def test_tls_client_hello(
    pytestconfig,
    tcpdump,
    curl_binary,
    env_vars,
    ld_preload,
    browser_signatures,
    expected_signature,
    test_urls,
):
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
        # requires more work to be functional.
        if not sys.platform.startswith("linux"):
            pytest.skip()

        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )

    test_urls = test_urls[0:2]
    ret = _run_curl(curl_binary, env_vars=env_vars, extra_args=None, urls=test_urls)
    assert ret == 0

    try:
        pcap, stderr = tcpdump.communicate(timeout=5)

        # If tcpdump finished running before timeout, it's likely it failed
        # with an error.
        assert tcpdump.returncode == 0, (
            f"tcpdump failed with error code {tcpdump.returncode}, " f"stderr: {stderr}"
        )
    except subprocess.TimeoutExpired:
        tcpdump.kill()
        pcap, stderr = tcpdump.communicate(timeout=3)

    assert len(pcap) > 0
    logging.debug(f"Captured pcap of length {len(pcap)} bytes")

    client_hellos = parse_pcap(pcap)
    # A client hello message for each URL
    assert len(client_hellos) == len(test_urls)

    logging.debug(
        f"Found {len(client_hellos)} Client Hello messages, "
        f"comparing to signature '{expected_signature}'"
    )

    for client_hello in client_hellos:
        # sig = TLSClientHelloSignature.from_bytes(client_hello)
        sig = client_hello["signature"]
        expected_sig = TLSClientHelloSignature.from_dict(
            browser_signatures[expected_signature]["signature"]["tls_client_hello"]
        )

        allow_tls_permutation = (
            browser_signatures[expected_signature]["signature"]
            .get("options", {})
            .get("tls_permute_extensions", False)
        )

        equals, reason = expected_sig.equals(sig, allow_tls_permutation)
        assert equals, reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, expected_signature",
    CURL_BINARIES_AND_SIGNATURES,
)
async def test_http2_headers(
    pytestconfig,
    nghttpd,
    curl_binary,
    env_vars,
    ld_preload,
    browser_signatures,
    expected_signature,
):
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )
    if ld_preload:
        # Injecting libcurl-impersonate with LD_PRELOAD is supported on
        # Linux only. On Mac there is DYLD_INSERT_LIBRARIES but it
        # requires more work to be functional.
        if not sys.platform.startswith("linux"):
            pytest.skip()

        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k"],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=2)

    assert len(output) > 0
    sig = parse_nghttpd_log(output)

    logging.debug(f"Received {len(sig.frames)} HTTP/2 frames")

    expected_sig = HTTP2Signature.from_dict(
        browser_signatures[expected_signature]["signature"]["http2"]
    )

    equals, msg = sig.equals(expected_sig)
    assert equals, msg


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload, expected_signature",
    CURL_BINARIES_AND_SIGNATURES,
)
def test_content_encoding(
    pytestconfig,
    curl_binary,
    env_vars,
    ld_preload,
    expected_signature,
    test_urls,
):
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
        # requires more work to be functional.
        if not sys.platform.startswith("linux"):
            pytest.skip()

        _set_ld_preload(
            env_vars,
            os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
        )

    output = tempfile.mkstemp()[1]
    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=None,
        urls=[test_urls[0]],
        output=output,
    )
    assert ret == 0

    with open(output, "r") as f:
        body = f.read()
        assert (
            "<!DOCTYPE html>" in body or "<html>" in body or "<!doctype html>" in body
        )


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload",
    [
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate-chrome",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "ff102", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate-ff",
        ),
    ],
)
async def test_no_builtin_headers(
    pytestconfig, nghttpd, curl_binary, env_vars, ld_preload
):
    """
    Ensure the built-in headers of libcurl-impersonate are not added when
    the CURL_IMPERSONATE_HEADERS environment variable is set to "no".
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )

    if not sys.platform.startswith("linux"):
        pytest.skip()

    _set_ld_preload(
        env_vars,
        os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
    )

    # Use some custom headers with a specific order.
    # We will test that the headers are sent in the exact given order, as
    # it is important for users to be able to control the exact headers
    # content and order.
    headers = [
        "X-Hello: World",
        "Accept: application/json",
        "X-Goodbye: World",
        "Accept-Encoding: deflate, gzip, br" "X-Foo: Bar",
        "User-Agent: curl-impersonate",
    ]
    header_args = list(itertools.chain(*[["-H", header] for header in headers]))

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k"] + header_args,
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)

    assert len(output) > 0
    sig = parse_nghttpd_log(output)
    for frame in sig.frames:
        if frame.frame_type == "HEADERS":
            headers_frame = frame
    for i, header in enumerate(headers_frame.headers):
        assert header.lower() == headers[i].lower()


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload",
    [
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101"},
            "libcurl-impersonate-chrome",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate-chrome",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "ff102"},
            "libcurl-impersonate-ff",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "ff102", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate-ff",
        ),
    ],
)
async def test_user_agent(pytestconfig, nghttpd, curl_binary, env_vars, ld_preload):
    """
    Ensure that any user-agent set with CURLOPT_HTTPHEADER will override
    the one set by libcurl-impersonate.
    """
    curl_binary = os.path.join(
        pytestconfig.getoption("install_dir"), "bin", curl_binary
    )

    if not sys.platform.startswith("linux"):
        pytest.skip()

    _set_ld_preload(
        env_vars,
        os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
    )

    user_agent = "My-User-Agent"

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k", "-H", f"User-Agent: {user_agent}"],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)

    assert len(output) > 0

    sig = parse_nghttpd_log(output)
    for frame in sig.frames:
        if frame.frame_type == "HEADERS":
            headers_frame = frame
    assert any(
        [header.lower().startswith("user-agent:") for header in headers_frame.headers]
    )

    for header in headers_frame.headers:
        if header.lower().startswith("user-agent:"):
            assert header[len("user-agent:") :].strip() == user_agent


@pytest.mark.parametrize(
    "curl_binary, env_vars, ld_preload",
    [
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101"},
            "libcurl-impersonate-chrome",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "chrome101", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate-chrome",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "ff102"},
            "libcurl-impersonate-ff",
        ),
        (
            "minicurl",
            {"CURL_IMPERSONATE": "ff102", "CURL_IMPERSONATE_HEADERS": "no"},
            "libcurl-impersonate-ff",
        ),
    ],
)
async def test_user_agent_curlopt_useragent(
    pytestconfig, nghttpd, curl_binary, env_vars, ld_preload
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

    _set_ld_preload(
        env_vars,
        os.path.join(pytestconfig.getoption("install_dir"), "lib", ld_preload),
    )

    user_agent = "My-User-Agent"

    ret = _run_curl(
        curl_binary,
        env_vars=env_vars,
        extra_args=["-k", "-A", user_agent],
        urls=["https://localhost:8443"],
    )
    assert ret == 0

    output = await _read_proc_output(nghttpd, timeout=5)

    assert len(output) > 0

    sig = parse_nghttpd_log(output)
    for frame in sig.frames:
        if frame.frame_type == "HEADERS":
            headers_frame = frame
    headers = headers_frame.headers
    assert any([header.lower().startswith("user-agent:") for header in headers])

    for header in headers:
        if header.lower().startswith("user-agent:"):
            assert header[len("user-agent:") :].strip() == user_agent
