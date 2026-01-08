// Chrupcio.cpp : Defines the entry point for the application.
//

#include "Chrupcio.h"
#include "service/ServiceInstaller.h"
#include "service/CThreadPool.h"
#include "service/ServiceException.h"
#include "execute_unit/CommandManager.h"
#include "logging/Logging.h"
#include "utils/StringConversion.h"
#include <filesystem>
#include <chrono>

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
		throw CServiceException(EVENTLOG_ERROR_TYPE, GetLastError(), L"Create Event StoppedEvent failed");
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
    // Ensure logging is initialized (idempotent) so that service logs are
    // captured when running as a service.
    Logging::initLogging();

    // Log a service start message to the Application log and to the logging system.
    WriteEventLogEntry(EVENTLOG_INFORMATION_TYPE, (PWSTR)L"WindowsService in OnStart");
    Logging::info("WindowsService OnStart");

    // Queue the main service function for execution in a worker thread.
    CThreadPool::QueueUserWorkItem(&CWindowsService::ServiceWorkerThread, this);
}

void CWindowsService::ServiceWorkerThread(void)
{
	try
	{
		// Periodically check if the service is stopping.
		while (!m_fStopping)
		{
			Sleep(2000);
		}

		// Signal the stopped event.
		SetEvent(m_hStoppedEvent);
	}
	catch (CServiceException& e)
	{
		// Log the error.
		WriteEventLogEntry(e.whatType(), e.whatMessage());
		{
			std::wstring ws(e.whatMessage());
			Logging::error("ServiceWorkerThread exception: {} (appCode={})", ToUtf8(ws), e.whatAppCode());
		}

		// Signal the stopped event.
		SetEvent(m_hStoppedEvent);

		// Set the service status to be stopped.
		Stop();
	}
}

void CWindowsService::OnStop()
{
    // Log a service stop message to the Application log.
    WriteEventLogEntry(EVENTLOG_INFORMATION_TYPE, (PWSTR)L"WindowsService in OnStop");
    Logging::info("WindowsService OnStop");

    // Indicate that the service is stopping and wait for the finish of the 
    // main service function (ServiceWorkerThread).
    m_fStopping = TRUE;
    if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    {
        throw CServiceException(EVENTLOG_ERROR_TYPE, GetLastError(), L"WaitForSingleObject StoppedEvent failed");
    }

    // Shutdown logging now that the service is stopped (idempotent).
    Logging::shutdownLogging();
}

int main(int argc, const char* argv[])
{
    // Initialize logging centrally
    Logging::initLogging();
    Logging::info("Chrupcio starting (pid={})", GetCurrentProcessId());

    if ((argc > 1) && ((*argv[1] == '-' || (*argv[1] == '/'))))
    {
        if (_stricmp("install", argv[1] + 1) == 0)
        {
            Logging::info("Installing service");
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
            Logging::info("InstallService returned");
        }
        else if (_stricmp("remove", argv[1] + 1) == 0)
        {
            Logging::info("Uninstalling service");
            // Uninstall the service when the command is 
            // "-remove" or "/remove".
            UninstallService((PWSTR)SERVICE_NAME);
            Logging::info("UninstallService returned");
        }
    }
    else
    {
        CWindowsService service((PWSTR)SERVICE_NAME);
        Logging::info("Running service...");
        if (!CWindowsService::Run(service))
        {
            auto err = GetLastError();
            Logging::error("Service failed to run w/err 0x{:08x}", err);
            printf("Service failed to run w/err 0x%08lx\n", err);
        }
        Logging::info("Service run finished");
    }

    Logging::info("Chrupcio exiting");
    // Ensure logs are flushed and background flush thread stopped
    Logging::shutdownLogging();
    return 0;
}