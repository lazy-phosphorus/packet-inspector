#include "strerror.h"

#include <errno.h>
#include <string.h>

Error Strerror() {
    Error temp;
    temp.message = strerror(errno);
    temp.length = strlen(temp.message);
    return temp;
}
