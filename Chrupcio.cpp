// Chrupcio.cpp : Defines the entry point for the application.
//

#include "Chrupcio.h"
#include "service/ServiceInstaller.h"
#include "service/CThreadPool.h"
#include "pcap/NetworkWatcher.h"

CWindowsService::CWindowsService(PWSTR pszServiceName,
    BOOL fCanStop,
    BOOL fCanShutdown,
    BOOL fCanPauseContinue) : CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue)
{
    m_fStopping = FALSE;

    // Create a manual-reset event that is not signaled at first to indicate 
    // the stopped signal of the service.
    m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_hStoppedEvent == NULL)
    {
        throw ServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorWrapper(GetLastError()), L"Create Event StoppedEvent failed");
    }
}


CWindowsService::~CWindowsService(void)
{
    if (m_hStoppedEvent)
    {
        CloseHandle(m_hStoppedEvent);
        m_hStoppedEvent = NULL;
    }
}

void CWindowsService::OnStart(DWORD dwArgc, LPWSTR* lpszArgv)
{
    // Log a service start message to the Application log.
    WriteEventLogEntry(EVENTLOG_INFORMATION_TYPE, (PWSTR)L"WindowsService in OnStart");

    // Queue the main service function for execution in a worker thread.
    CThreadPool::QueueUserWorkItem(&CWindowsService::ServiceWorkerThread, this);
}

void CWindowsService::ServiceWorkerThread(void)
{

    CNetworkWatcher networkWatcher = CNetworkWatcher((PWSTR)"\\Device\\NPF_{8CDF54B9-41F5-4B0E-8C05-A7A7ACFB5243}");
    // Periodically check if the service is stopping.
    while (!m_fStopping)
    {
        networkWatcher.nextPacket();
    }

    // Signal the stopped event.
    SetEvent(m_hStoppedEvent);
}

void CWindowsService::OnStop()
{
    // Log a service stop message to the Application log.
    WriteEventLogEntry(EVENTLOG_INFORMATION_TYPE, (PWSTR)"WindowsService in OnStop");

    // Indicate that the service is stopping and wait for the finish of the 
    // main service function (ServiceWorkerThread).
    m_fStopping = TRUE;
    if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    {
        throw GetLastError();
    }
}

int main(int argc, const char* argv[])
{
    if ((argc > 1) && ((*argv[1] == '-' || (*argv[1] == '/'))))
    {
        if (_stricmp("install", argv[1] + 1) == 0)
        {
            // Install the service when the command is 
            // "-install" or "/install".

            InstallService(
                (PWSTR)SERVICE_NAME,               // Name of service
                (PWSTR)SERVICE_DISPLAY_NAME,       // Name to display
                SERVICE_START_TYPE,         // Service start type
                (PWSTR)SERVICE_DEPENDENCIES,       // Dependencies
                (PWSTR)SERVICE_ACCOUNT,            // Service running account
                SERVICE_PASSWORD            // Password of the account
            );
        }
        else if (_stricmp("remove", argv[1] + 1) == 0)
        {
            // Uninstall the service when the command is 
            // "-remove" or "/remove".
            UninstallService((PWSTR)SERVICE_NAME);
        }
        else if (_stricmp("list_devs", argv[1] + 1) == 0)
        {
            // List all devices when the command is 
            // "-list_devs" or "/list_devs".
            char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
            pcap_if_t* it = NULL;

            if (pcap_findalldevs(&it, errbuf) == 0) {
                while (it) {
                    printf("%s - %s\n", it->name, it->description);
                    it = it->next;
                }
                pcap_freealldevs(it);
            }
        }
    }
    else
    {
        CWindowsService service((PWSTR)SERVICE_NAME);
        if (!CWindowsService::Run(service))
        {
            printf("Service failed to run w/err 0x%08lx\n", GetLastError());
        }
    }
	return 0;
}
