#pragma once
#include <iostream>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <yara.h>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>
#include <filesystem>
#include <algorithm>
#include <windows.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <Psapi.h>
#include <unordered_map>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")


std::string getDigitalSignature(const std::string& filePath);
std::string convertToPath(const std::string& path);
bool isAPath(const std::string& path);


struct GenericRule {
    std::string name;
    std::string rule;
};

extern std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule);

void initializeGenericRules();

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules);