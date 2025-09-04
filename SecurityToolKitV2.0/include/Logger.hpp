

#ifndef SECURITYTOOLKIT_LOGGER_HPP

#define SECURITYTOOLKIT_LOGGER_HPP

#include <string>
#include <iostream>
#include <fstream>
#include <mutex>
#include <map>
#include"../Utils/NonCopyable.hpp"


//defines the log levels
enum class LogLevel {

	INFO,//informational messages
	WARNING,//warnings
	ERROR,//errors
	CRITICAL//critical warnings(can affect the work of the application)

};

class Logger : NonCopyable {

public:

	//Singleton pattern: makes global access to logger object
	static Logger& instance();

	void log(LogLevel level, const std::string& message);
	
	void setLogFile(const std::string& log_file);

private:
	//Making Constructor and destructor private
	//this, makes this class can only have 1 object (Singleton)

	Logger();
	~Logger();



	std::ofstream logFile;
	std::mutex logMutex;
	std::map<LogLevel, std::string> levelStrings;
	std::map<LogLevel, int> colorCodes;

	void logToConsole(LogLevel level, const std::string& message);
	void logToFile(LogLevel level, const std::string& message);

};




#endif //SECURITYTOOLKIT_LOGGER_HPP