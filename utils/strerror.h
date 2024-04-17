#ifndef __STRERROR__
#define __STRERROR__

typedef struct {
    const char *message;
    int length;
} Error;

Error Strerror();

#endif  // __STRERROR__