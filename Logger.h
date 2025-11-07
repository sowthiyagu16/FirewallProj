#pragma once

#include <windows.h>
#include <string>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <ctime>
#include <iostream>
#include "TpmSigner.h"
#include "stdafx.h"


class Logger
{
public:
    Logger(const std::string& logDirectory, const TpmSigner& signer);
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Log Events
    void log(const std::string& firewallstatus, const std::string& action, 
        const std::string& profile, bool result, const std::string& notes);
    void log(const std::string& log);
   
private:
    std::string logDir;
    std::string filename;   
    std::ofstream logfile;
    TpmSigner tpmSigner;    

    std::string getCurrentTimestamp();
    void initilizeLogFile();
};

