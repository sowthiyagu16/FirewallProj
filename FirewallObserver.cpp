
#include <iostream>
#include <windows.h>
#include <netfw.h>
#include "FilrewallService.h"
#include "TpmSignVerifier.h"

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

BOOL WINAPI ConsoleHandler(DWORD signal)
{
    switch (signal)
    {
    case CTRL_C_EVENT:
        std::cout << "Ctrl+C pressed!\n";
        break;
    case CTRL_BREAK_EVENT:
        std::cout << "Ctrl+Break pressed!\n";
        break;
    case CTRL_CLOSE_EVENT:
        std::cout << "Console window is closing!\n";
        // Perform cleanup here
        break;
    case CTRL_LOGOFF_EVENT:
        std::cout << "User is logging off!\n";
        break;
    case CTRL_SHUTDOWN_EVENT:
        std::cout << "System is shutting down!\n";
        break;
    default:
        std::cout << "Unknown signal: " << signal << std::endl;
        break;
    }
    if (FilrewallService::instance)
    {
        FilrewallService::instance->StopService();
    }
    return TRUE; // indicate we handled the signal
}

int main()
{
    // Register the handler
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE))
    {
        std::cerr << "Error: Could not set control handler.\n";
        return 1;
    }

    try
    {
        ElevateIfRequired();
        std::cout << "Application is running with administrative privileges." << std::endl;
        TpmSigner signer;
        Logger logger("c:\\Firewall_monitor_logs", signer);
        FilrewallService firewallService(logger);
        firewallService.StartService();

        while (firewallService.IsServiceRunning())
        {
            Sleep(500); // Main loop sleep
        }
        std::cout << "Application execution completed successfully." << std::endl;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "An unexpected error occurred: " << ex.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }

    std::cout << "Console running. Press Ctrl+C or close the window.\n";
    return 0;
}

int main1()
{
    TpmSignVerifier verifier;
    verifier.VerifyFileWithTPM(L"C:\\logs\\2025-11-05.log", L"C:\\logs\\2025-11-05.sig");
    getchar();
    return 0;
}