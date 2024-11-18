#include <stdlib.h>
#include <stdio.h>
#include <openssl/x509.h>

int main() {
    const char *dir = getenv(X509_get_default_cert_dir_env());

    dir = X509_get_default_cert_file();

    puts(dir);

    return 0;
}
