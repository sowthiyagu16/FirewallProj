#include "FilrewallService.h"
#include <iostream>
#include <sstream>
#include <vector>

FilrewallService* FilrewallService::instance = nullptr;
std::thread firewall_service_worker;

FilrewallService::FilrewallService(Logger& logger) : logger(logger) {
    DEBUG_LOG("Monitoring Firewall" << std::endl);
    instance = this; // set static pointer
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        std::cerr << "Failed to initialize COM library. Error: " << hr << std::endl;
        return;
    }

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr))
    {
        std::cerr << "Failed to create an instance of INetFwPolicy2. Error: " << hr << std::endl;
        CoUninitialize();
        return;
    }
}

FilrewallService::~FilrewallService()
{
    if (pNetFwPolicy2) {
        pNetFwPolicy2->Release();
        pNetFwPolicy2 = nullptr;
    }
    // Uninitialize the COM library
    CoUninitialize();
}
void FilrewallService::StopService() {

    if (!isRunning)
    {
        DEBUG_LOG("Service is not running \n");
        return;
    }

    DEBUG_LOG("Stopping Firewall Service...\n");

    if (firewall_service_worker.joinable())
    {
        isRunning = false;
        firewall_service_worker.join();
    }
    DEBUG_LOG("Firewall Service stopped successfully." << std::endl);
}


void FilrewallService::StartService()
{
    if (isRunning)
    {
        DEBUG_LOG("Service is already running.\n");
        return;
    }    
    isRunning = true;
    firewall_service_worker = std::thread(&FilrewallService::FirewallMonitorService, instance);
    DEBUG_LOG("Service is Started \n");

}

void FilrewallService::FirewallMonitorService()
{
    std::vector<NET_FW_PROFILE_TYPE2> profiles = {
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC
    };

    isRunning = true; // Set the running flag to true
    while (isRunning) {
        for (const auto& profile : profiles) {            
            // Example: Check if the firewall is enabled for each profile
            VARIANT_BOOL firewallEnabled;
            HRESULT hr = pNetFwPolicy2->get_FirewallEnabled(profile, &firewallEnabled);
            if (SUCCEEDED(hr)) {
                DEBUG_LOG("Firewall is " << (firewallEnabled == VARIANT_TRUE ? "enabled" : "disabled") << " on profile " << profile << "." << std::endl);                
                if (firewallEnabled == VARIANT_FALSE) {
                    hr = pNetFwPolicy2->put_FirewallEnabled(profile, VARIANT_TRUE);
                    if (SUCCEEDED(hr))
                    {
                        std::wstring wsprofile = FirewallProfileToString(profile);
                        std::wstring wstr = std::wstring(L"[Firewall] Domain profile '") + wsprofile + L"' set to ENABLED.";
                        std::string message(wstr.begin(), wstr.end());
                        std::cout<<message << std::endl;
                        logger.log(message);
                    }
                    else {
                        DEBUG_LOG("Failed to toggle firewall state for domain profile\n");
                    }
                }
            }
            else {
                std::cerr << "Failed to get firewall status for profile "
                    << profile << ". Error: " << hr << std::endl;
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}



bool FilrewallService::IsServiceRunning() const {
    return isRunning;
}


std::wstring FilrewallService::FirewallProfileToString(const long& profileType)
{
    switch (profileType)
    {
    case NET_FW_PROFILE2_DOMAIN:  return L"Domain";
    case NET_FW_PROFILE2_PRIVATE: return L"Private";
    case NET_FW_PROFILE2_PUBLIC:  return L"Public";
    default:                      return L"Unknown";
    }
}
