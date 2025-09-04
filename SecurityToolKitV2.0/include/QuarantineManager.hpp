#ifndef SECURITYTOOLKIT_QUARANTINEMANAGER_HPP
#define SECURITYTOOLKIT_QUARANTINEMANAGER_HPP

#include <string>
#include <vector>
#include <mutex>
#include"../Utils/NonCopyable.hpp"

class QuarantineManager : NonCopyable {

public:

	static QuarantineManager& instance();

	bool quarantineFile(const std::string& filePath, const std::string& threatName);

	bool restoreFile(const std::string& quarantinePath);

	std::vector<std::string> listQuarantinedFiles() const;


private:

	QuarantineManager();
	~QuarantineManager();


	std::string quarantineDir;
	std::mutex quarantineMutex;
};




#endif //SECURITYTOOLKIT_QUARANTINEMANAGER_HPP