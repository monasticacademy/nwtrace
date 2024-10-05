import socket
import requests

def main():
    # monkey-patch the global resolver
    socket.getaddrinfo = lambda domain_name, port, *args, **kwargs: [
        (socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM, 6, "", ("127.0.0.1", 37971))
    ]

    response = requests.get("https://example.com/", verify=True)
    print(response.text)


if __name__ == "__main__":
    main()
