
#include"../include/Logger.hpp"
#include <iostream>
#include <ctime>
#include <iomanip>

Logger& Logger::instance() {
	static Logger loggerInstance;
	return loggerInstance;
}

Logger::Logger() {

	//Texts and color codes corresponding to log levels

	levelStrings = {
		{LogLevel::INFO, "INFO"},
		 {LogLevel::WARNING, "WARNING"},
		{LogLevel::ERROR, "ERROR"},
		{LogLevel::CRITICAL, "CRITICAL"}
	};

	colorCodes = {
		{LogLevel::INFO, 32},       // Green
		{LogLevel::WARNING, 33},    // Yellow
		{LogLevel::ERROR, 31},      // Red
		{LogLevel::CRITICAL, 41}    // Red background
	};

}

Logger::~Logger() {

	if (logFile.is_open()) {
		logFile.close();
	}
}

void Logger::setLogFile(const std::string& filename) {
	std::lock_guard<std::mutex> lock(logMutex);

	if (logFile.is_open()) {
		logFile.close();
	}

	logFile.open(filename, std::ios::app); 
}

void Logger::log(LogLevel level, const std::string& message) {

	std::lock_guard<std::mutex> lock(logMutex);

	//log to the console
	logToConsole(level, message);

	if (logFile.is_open()) {
		logToFile(level, message);
	}
}

void Logger::logToConsole(LogLevel level, const std::string& message) {

	//get time
	std::time_t now = std::time(nullptr);
	std::tm timeinfo;

	//use localtime_s for security

	if (localtime_s(&timeinfo, &now) != 0) {
		std::cerr << "Timestamp error." << std::endl;
		return;
	}

	//Set the Console colors
	std::cout << "\033[" << colorCodes[level] << "m";


	// Format the message: [Time] [Level] Message
		// You can't use put_time with tm&, so you'll have to manually format the string
	std::cout << "[" << (timeinfo.tm_year + 1900) << "-"
		<< std::setw(2) << std::setfill('0') << (timeinfo.tm_mon + 1) << "-"
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_mday << " "
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_hour << ":"
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_min << ":"
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_sec << "] ";

	std::cout << "[" << levelStrings[level] << "] ";
	std::cout << message << "\033[0m" << std::endl; // Reset the colors.


}

void Logger::logToFile(LogLevel level, const std::string& message) {

	// get time
	std::time_t now = std::time(nullptr);
	std::tm timeinfo;

	// Use localtime_s for security
	if (localtime_s(&timeinfo, &now) != 0) {
		if (logFile.is_open()) {
			logFile << "Timestamp error." << std::endl;
		}
		return;
	}

	// write to file without color codes.
	logFile << "[" << (timeinfo.tm_year + 1900) << "-"
		<< std::setw(2) << std::setfill('0') << (timeinfo.tm_mon + 1) << "-"
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_mday << " "
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_hour << ":"
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_min << ":"
		<< std::setw(2) << std::setfill('0') << timeinfo.tm_sec << "] ";

	logFile << "[" << levelStrings[level] << "] ";
	logFile << message << std::endl;
}


