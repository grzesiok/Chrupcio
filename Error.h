#pragma once

#define ServiceError DWORD

#define ServiceErrorWrapper(windowsError) (0xf0000000 | windowsError)
#define ServiceErrorPCAPLookupNetFailed 1
#define ServiceErrorPCAPOpenLiveFailed 2
#define ServiceErrorPCAPDataLinkFailed 3
#define ServiceErrorPCAPCompileFailed 4
#define ServiceErrorPCAPSetFilterFailed 5