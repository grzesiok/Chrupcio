#pragma once
#include <Windows.h>
#include <strsafe.h>
#include "Status.h"

class CServiceException {

public:
    CServiceException(WORD wType, ServiceStatus dwAppCode, const wchar_t* pszMessage, ...) {
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

    ServiceStatus whatAppCode() const throw () {
        return m_dwAppCode;
    }

private:
    wchar_t m_szMessage[260];
    WORD m_wType;
    ServiceStatus m_dwAppCode;
};