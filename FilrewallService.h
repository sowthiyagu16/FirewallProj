#pragma once

#include "Logger.h"
#include "stdafx.h"
#include <netfw.h>
#include <thread>
#include <atomic>
#include <iostream>



class FilrewallService
{
public:
    FilrewallService(Logger&);
    ~FilrewallService();
    void StartService();
    void StopService();
    bool IsServiceRunning() const;
    static FilrewallService* instance;

private:
    INetFwPolicy2* pNetFwPolicy2 = NULL;
    std::atomic<bool> isRunning{ false };
    void FirewallMonitorService();
    Logger& logger;
    std::wstring FirewallProfileToString(const long& profileType);
};

