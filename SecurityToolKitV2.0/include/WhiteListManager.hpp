#ifndef SECURITYTOOLKIT_WHITELISTMANAGER_HPP
#define SECURITYTOOLKIT_WHITELISTMANAGER_HPP

#include <string>
#include <unordered_set>
#include <mutex>
#include <vector>
#include"../Utils/NonCopyable.hpp"


class WhitelistManager : NonCopyable {
public:
	
	//Singleton pattern : global access
	static WhitelistManager& instance();

	//loads the whitelist
	bool loadWhiteList(const std::string& fileName);

	//controls the hash in the whitelist
	bool isWhiteListed(const std::string& hash) const;


private:

	WhitelistManager();
	~WhitelistManager();

	std::unordered_set<std::string> whitelistedHashes;
	mutable std::mutex whiteListmutex;


};



#endif //SECURITYTOOLKIT_WHITELISTMANAGER_HPP