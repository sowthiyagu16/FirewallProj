#include "firewallObserverbridge.hxx"
#include "FilrewallService.h"
#include "Logger.h"
#include "TpmSigner.h"

bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
        {
            std::cerr << "Failed to check token membership. Error: " << GetLastError() << std::endl;
        }
        FreeSid(adminGroup);
    }
    else
    {
        std::cerr << "Failed to allocate and initialize SID. Error: " << GetLastError() << std::endl;
    }
    return isAdmin == TRUE;
}

void ElevateIfRequired()
{
    if (!IsRunAsAdmin())
    {
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0)
        {
            std::cerr << "Failed to get module file name. Error: " << GetLastError() << std::endl;
            exit(1);
        }

        // Relaunch elevated
        if ((int)ShellExecuteA(NULL, "runas", path, NULL, NULL, SW_SHOWNORMAL) <= 32)
        {
            std::cerr << "Failed to relaunch the application with elevated privileges. Error: " << GetLastError() << std::endl;
            exit(1);
        }
        exit(0); // stop current non-admin instance
    }
}


void start_service() {
    try
    {
        ElevateIfRequired();
        
        std::cout << "Application is running with administrative privileges." << std::endl;

        TpmSigner signer;
        Logger logger("C:\\Firewall_monitor_logs", signer);
        FilrewallService firewallService(logger);
        firewallService.StartService();      

        // Main loop
        while (firewallService.IsServiceRunning())
        {
            Sleep(500);
        }       
    }
    catch (const std::exception& ex)
    {
        std::cerr << "An unexpected error occurred: " << ex.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "An unknown error occurred." << std::endl;
    }
}

void stop_service() {    
}