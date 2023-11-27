#pragma once
#include <strsafe.h>

#define ServiceAppCode DWORD

#define ServiceErrorWrapper(errorCode) (errorCode | 0xf000000)
#define ServiceErrorPCAPLookupNetFailed 1
#define ServiceErrorPCAPOpenLiveFailed 2
#define ServiceErrorPCAPDataLinkFailed 3
#define ServiceErrorPCAPCompileFailed 4
#define ServiceErrorPCAPSetFilterFailed 5

class ServiceException {

public:
    ServiceException(WORD wType, ServiceAppCode dwAppCode, const wchar_t* pszMessage, ...) {
        va_list args;

        va_start(args, pszMessage);
        StringCchVPrintfW(m_szMessage, ARRAYSIZE(m_szMessage), pszMessage, args);
        va_end(args);
        m_wType = wType;
        m_dwAppCode = dwAppCode;
    }

    PWSTR whatMessage() const throw () {
        return (PWSTR)m_szMessage;
    }

    WORD whatType() const throw () {
        return m_wType;
    }

    ServiceAppCode whatAppCode() const throw () {
        return m_dwAppCode;
    }

private:
    wchar_t m_szMessage[260];
    WORD m_wType;
    ServiceAppCode m_dwAppCode;
};