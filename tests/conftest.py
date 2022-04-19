def pytest_addoption(parser):
    # Where to find curl-impersonate's binaries
    parser.addoption("--install-dir", action="store", default="/usr/local")
    parser.addoption("--capture-interface", action="store", default="eth0")
