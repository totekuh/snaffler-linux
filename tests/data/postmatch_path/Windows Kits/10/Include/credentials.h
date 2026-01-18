// Windows SDK header file - false positive
// credentials.h

#ifndef _CREDENTIALS_H_
#define _CREDENTIALS_H_

typedef struct _CREDENTIAL {
    DWORD Flags;
    DWORD Type;
    LPTSTR TargetName;
} CREDENTIAL;

#endif
