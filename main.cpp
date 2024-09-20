#define _CRT_SECURE_NO_WARNINGS
#include "includes.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

const char* DEFAULT_OUTPUT_PATH = "activity_log.txt";
const long long MIN_DB_SIZE = 1300000;

struct ActivityData {
    std::string sourceTable;
    std::string appId;
    std::string startTime;
    std::string endTime;
    time_t startTimeUnix;
};

std::string unixTimeToString(const std::string& unixTime) {
    std::istringstream iss(unixTime);
    long long t;
    iss >> t;
    std::time_t time = static_cast<time_t>(t);
    std::tm* tm = std::localtime(&time);
    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
    return std::string(buffer);
}

static int callback(void* data, int argc, char** argv, char** azColName) {
    auto* activities = static_cast<std::pair<std::vector<ActivityData>*, std::string>*>(data);
    ActivityData activity;
    activity.sourceTable = activities->second;

    for (int i = 0; i < argc; i++) {
        std::string columnName = azColName[i];
        std::string value = argv[i] ? argv[i] : "NULL";

        if (columnName == "AppId") {
            activity.appId = value;
        }
        else if (columnName == "StartTime") {
            activity.startTime = unixTimeToString(value);
            std::istringstream iss(value);
            iss >> activity.startTimeUnix;
        }
        else if (columnName == "EndTime") {
            activity.endTime = unixTimeToString(value);
        }
    }

    activities->first->push_back(activity);
    return 0;
}
std::string extractApplicationPath(const std::string& appId) {
    try {
        json appIdJson = json::parse(appId);
        for (const auto& item : appIdJson) {
            if (item.contains("platform") &&
                (item["platform"] == "x_exe_path" || item["platform"] == "windows_win32")) {
                if (item.contains("application")) {
                    return item["application"];
                }
            }
        }
    }
    catch (json::parse_error& e) {
    }
    return "";
}

bool isRelevantPlatform(const std::string& appId) {
    return !extractApplicationPath(appId).empty();
}

void writeToFile(std::vector<ActivityData>& activities, const std::string& filePath, bool onlyNotSigned) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::time_t four_days_ago = now_time - (4 * 24 * 60 * 60);
    std::sort(activities.begin(), activities.end(), [](const ActivityData& a, const ActivityData& b) {
        return a.startTimeUnix > b.startTimeUnix;
        });

    std::ofstream outFile(filePath, std::ios::app);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open output file: " << filePath << std::endl;
        return;
    }

    for (const auto& activity : activities) {
        if (activity.startTimeUnix < four_days_ago) {
            break;
        }

        std::string applicationPath = extractApplicationPath(activity.appId);
        std::string convertedPath = convertToPath(applicationPath);
        if (!isAPath(convertedPath)) {
            continue;
        }

        std::string digitalSignature = getDigitalSignature(convertedPath);
        bool isSigned = (digitalSignature == "Signed");

        if (onlyNotSigned && isSigned) {
            continue;
        }

        outFile << "Application: " << convertedPath << std::endl;
        outFile << "Digital signature: " << digitalSignature << std::endl;

        if (!isSigned) {
            std::vector<std::string> matched_rules;
            bool yara_match = scan_with_yara(convertedPath, matched_rules);
            outFile << "Generics: ";
            if (yara_match) {
                for (const auto& rule : matched_rules) {
                    outFile << "Flagged [" << rule << "]  ";
                }
            }
            else {
                outFile << "none";
            }
            outFile << std::endl;
        }

        outFile << "StartTime: " << activity.startTime << std::endl;
        outFile << "EndTime: " << activity.endTime << std::endl;
        outFile << "------------------------" << std::endl;
    }

    outFile.close();
}



void processDatabase(const fs::path& dbPath, const std::string& outputPath, bool onlyNotSigned) {
    sqlite3* db;
    char* zErrMsg = 0;
    int rc;
    std::vector<ActivityData> activities;

    rc = sqlite3_open(dbPath.string().c_str(), &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    std::vector<std::string> tables = { "Activity", "ActivityOperation" };

    for (const auto& table : tables) {
        auto start = std::chrono::high_resolution_clock::now();
        std::string sql = "SELECT AppId, StartTime, EndTime FROM " + table + ";";
        std::pair<std::vector<ActivityData>*, std::string> callbackData(&activities, table);
        rc = sqlite3_exec(db, sql.c_str(), callback, &callbackData, &zErrMsg);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        if (rc != SQLITE_OK) {
            std::cerr << "SQL error in table " << table << ": " << zErrMsg << std::endl;
            sqlite3_free(zErrMsg);
        }
        else {
           // std::cout << "Query successful. Activities retrieved from " << table << " in " << dbPath << ": " << activities.size() << std::endl;
           // std::cout << "Time taken for " << table << ": " << duration.count() << " milliseconds" << std::endl;
        }
    }

    writeToFile(activities, outputPath, onlyNotSigned);
    std::cout << "Activities written to: " << outputPath << std::endl;

    sqlite3_close(db);
}

std::string getUserName() {
    char* userProfile = std::getenv("USERPROFILE");
    if (userProfile == nullptr) {
        std::cerr << "Unable to get user profile path." << std::endl;
        return "";
    }
    fs::path userProfilePath(userProfile);
    return userProfilePath.filename().string();
}

void searchAndProcessDatabases(const std::string& outputPath, bool onlyNotSigned) {
    std::string userName = getUserName();
    if (userName.empty()) return;

    fs::path basePath = fs::path("C:\\Users") / userName / "AppData\\Local\\ConnectedDevicesPlatform";

    if (!fs::exists(basePath) || !fs::is_directory(basePath)) {
        std::cerr << "ConnectedDevicesPlatform directory not found." << std::endl;
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(basePath)) {
        if (entry.is_regular_file() && entry.path().filename() == "ActivitiesCache.db") {
            if (fs::file_size(entry.path()) > MIN_DB_SIZE) {
                std::cout << "Processing database: " << entry.path() << std::endl;
                processDatabase(entry.path(), outputPath, onlyNotSigned);
            }
            else {
                std::cout << "Skipping small database: " << entry.path() << std::endl;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    auto start = std::chrono::high_resolution_clock::now();
    std::string outputPath = DEFAULT_OUTPUT_PATH;
    bool openInNotepad = true;
    bool onlyNotSigned = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-n" || arg == "--not-signed") {
            onlyNotSigned = true;
        }
        else {
            outputPath = arg;
            openInNotepad = false;
        }
    }

    std::ofstream clearFile(outputPath, std::ios::trunc);
    clearFile.close();

    initializeGenericRules();
    searchAndProcessDatabases(outputPath, onlyNotSigned);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Total time taken: " << duration.count() << " milliseconds" << std::endl;

    if (openInNotepad) {
        std::string command = "notepad.exe " + outputPath;
        system(command.c_str());
    }

    return 0;
}
