#include "Logger.h"


// constructor
Logger::Logger(const std::string& logDirectory, const TpmSigner& signer) : 
                            logDir(logDirectory), tpmSigner(signer)
{

    if (logDir.empty()) {
        logDir = "logs";
        char buffer[MAX_PATH];

        DWORD length = GetCurrentDirectoryA(MAX_PATH, buffer);
        if (length == 0 || length > MAX_PATH) {
            std::cerr << "Failed to get current directory.\n";
        }
        else
        {
            logDir = std::string(buffer) + "\\" + logDir;
        }
    }

    // Create directory
    if (CreateDirectoryA(logDir.data(), NULL)) {
        DEBUG_LOG("Directory created successfully.\n");
    }
    else {
        DWORD error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS)
            DEBUG_LOG( "Directory already exists.\n");
        else
            std::cerr << "Failed to create directory. Error code: " << error << "\n";
    }   
    std::cout << "Log Directory: " << logDir << std::endl;
    initilizeLogFile();
}

// Get current timestamp in "YYYY-MM-DD HH:MM:SS" format
std::string Logger::getCurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    std::tm timeInfo;
    localtime_s(&timeInfo, &now_c); // Use localtime_s for thread safety

    std::ostringstream oss{};
    oss << std::put_time(&timeInfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Log function
void Logger::log(const std::string& firewallstatus, const std::string& action, const std::string& profile, bool result, const std::string& notes)
{

    if (logfile.is_open())
    {
        logfile << "[" << getCurrentTimestamp() << "] "
            << "Firewall Status: " << firewallstatus << ", "
            << "Action: " << action << ", "
            << "Profile: " << profile << ", "
            << "Result: " << (result ? "Success" : "Failure") << ", "
            << "Notes: " << notes
            << std::endl;
        logfile.flush();
        tpmSigner.signfile(logDir + "/" + filename);
    }
}

// Log function for simple messages
void Logger::log(const std::string& log)
{
    if (logfile.is_open())
    {
        logfile << "[" << getCurrentTimestamp() << "] "
            << log << std::endl;
        logfile.flush();
        tpmSigner.signfile(logDir + "/" + filename);
    }
    else {
        std::cerr << "Log file is not open.\n";
    }

}

Logger::~Logger()
{
    if (logfile.is_open()) {
        logfile.close();
    }
}

// Initialize log file
void Logger::initilizeLogFile()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    std::tm timeInfo;
    localtime_s(&timeInfo, &now_c); 

    std::ostringstream oss;    
    oss << "Report_" << std::put_time(&timeInfo, "%Y-%m-%d_%H-%M-%S") << ".log";
    filename = oss.str();
    std::cout << "Log File: " << filename << std::endl;
    logfile.open(logDir + "/" + filename);

    if (logfile.is_open())
    {
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName) / sizeof(computerName[0]);
        if (GetComputerNameA(computerName, &size)) {
            logfile << "Computer Name: " << computerName << std::endl;
            logfile << "Log File Created on: " << getCurrentTimestamp() << std::endl;
            logfile.flush();
        }
        else {
            std::cerr << "Failed to create log file.\n";
        }
    }
    tpmSigner.signfile(logDir + "/" + filename);
}