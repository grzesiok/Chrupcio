// Chrupcio.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include "service\ServiceBase.h"
#include "Error.h"

// Internal name of the service
#define SERVICE_NAME             L"Chrupcio"

// Displayed name of the service
#define SERVICE_DISPLAY_NAME     L"Chrupcio Service"

// Service start options.
#define SERVICE_START_TYPE       SERVICE_DEMAND_START

// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES     L""

// The name of the account under which the service should run
#define SERVICE_ACCOUNT          L"NT AUTHORITY\\LocalService"

// The password to the service account name
#define SERVICE_PASSWORD         NULL

class CWindowsService : public CServiceBase
{
public:
    CWindowsService(PWSTR pszServiceName,
        BOOL fCanStop = TRUE,
        BOOL fCanShutdown = TRUE,
        BOOL fCanPauseContinue = FALSE);
    ~CWindowsService(void);

protected:
    virtual void OnStart(DWORD dwArgc, PWSTR* pszArgv);
    virtual void OnStop();

    void ServiceWorkerThread(void);
private:
    BOOL m_fStopping;
    HANDLE m_hStoppedEvent;
};
