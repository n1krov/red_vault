#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    
    // setuid a 0 porque el programa se ejecuta como root
    setuid(0);
    printf("\n[+] Acuktalmente soy el sigueinte usuario:\n\n");
    system("/usr/bin/whoami");

    printf("\n[+] Acuktalmente soy el sigueinte usuario:\n\n");
    system("whoami");



    return 0;
}
