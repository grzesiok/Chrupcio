// Chrupcio.cpp : Defines the entry point for the application.
//

#include "Chrupcio.h"
#include "service/ServiceInstaller.h"
#include "service/CThreadPool.h"
#include "service/ServiceException.h"
#include "pcap/NetworkWatcher.h"
#include "execute_unit/CommandManager.h"
#include "pcap/PacketAnalyzeCommand.h"
#include <pqxx/pqxx>

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

	m_cmdManager.addCommand("PACKET_ANALYZE", new PacketAnalyzeCommand());
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

	m_db = new pqxx::connection("dbname = chrupcio user = postgres password = ?? hostaddr = 127.0.0.1 port = 5432");
	if (m_db->is_open()) {
		WriteEventLogEntry(EVENTLOG_INFORMATION_TYPE, (PWSTR)L"Opened database successfully: %S", m_db->dbname());
	}
	else {
		delete m_db;
		m_db = NULL;
		throw CServiceException(EVENTLOG_ERROR_TYPE, 1, (PWSTR)L"Can't open database");
	}

	// Queue the main service function for execution in a worker thread.
	CThreadPool::QueueUserWorkItem(&CWindowsService::ServiceWorkerThread, this);
}

void CWindowsService::ServiceWorkerThread(void)
{
	try
	{
		CNetworkWatcher networkWatcher = CNetworkWatcher("\\Device\\NPF_{2C02A749-E12B-4F4E-B46A-4BD5094AA41D}",
			"ip and not (dst net 192.168.0.0/16 and src net 192.168.0.0/16)");
		// Periodically check if the service is stopping.
		/* Prepare SQL statement template */
		m_db->prepare("packets_insert", "INSERT INTO packets (ts_sec,ts_usec,eth_src,eth_dst) VALUES ($1, $2, $3, $4);");
		/* Create a transactional object. */
		pqxx::work W(*m_db);
		while (!m_fStopping)
		{
			SNetworkPacket networkPacket = networkWatcher.nextPacket();
			SJob job("PACKET_ANALYZE", &networkPacket, sizeof(SNetworkPacket));
			uint32_t retCode = m_cmdManager.jobExecute(job, JobModeSynchronous, JobQueueTypeNone);
			if (retCode) {
				WriteEventLogEntry(EVENTLOG_ERROR_TYPE, (PWSTR)L"PACKET_ANALYZE return with code %u", retCode);
			}
			else {
				/* Execute SQL query */
				W.exec_prepared("packets_insert", 1, 2, 3, 4);
				W.commit();
			}
		}

		// Signal the stopped event.
		SetEvent(m_hStoppedEvent);
	}
	catch (CServiceException& e)
	{
		// Log the error.
		WriteEventLogEntry(e.whatType(), e.whatMessage());

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
	// Indicate that the service is stopping and wait for the finish of the 
	// main service function (ServiceWorkerThread).
	m_fStopping = TRUE;
	if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
	{
		throw CServiceException(EVENTLOG_ERROR_TYPE, GetLastError(), L"WaitForSingleObject StoppedEvent failed");
	}
	if (m_db) {
		m_db->close();
		delete m_db;
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
					printf("%s - %s", it->name, it->description);
					if (it->addresses)
					{
						struct sockaddr* addr = it->addresses->addr;
						switch (addr->sa_family) {
						case AF_INET: {
							struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
							char s[INET_ADDRSTRLEN];
							printf(" -> %s\n", s);
							inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
							break;
						}
						case AF_INET6: {
							struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
							char s[INET6_ADDRSTRLEN];
							printf(" -> %s\n", s);
							inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
							break;
						}
						default:
							break;
						}
					}
					else {
						printf(" -> NONE\n");
					}
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
