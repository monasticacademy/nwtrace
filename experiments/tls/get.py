import socket
import requests
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    # monkey-patch the global resolver
    socket.getaddrinfo = lambda domain_name, port, *argv, **kwargs: [
        (socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM, 6, "", ("127.0.0.1", args.port))
    ]

    response = requests.get("https://example.com/", verify=True)
    print(response.text.strip())


if __name__ == "__main__":
    main()
