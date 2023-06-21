#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <memory>

namespace swss {

class RecBase {
public:
    RecBase() {}
    /* Setters */
    void setRecord(bool record)  { enable_rec = record; }
    void setRotate(bool rotate)  { log_rotate = rotate; }
    void setLocation(const std::string& loc) { location = loc; }
    void setFileName(const std::string& name) { filename = name; }

    /* getters */
    bool isRecord()  { return enable_rec; }
    bool isRotate()  { return log_rotate; }
    std::string getLoc() { return location; }
    std::string getFile() { return filename; }

private:
    bool enable_rec;
    std::string location;
    std::string filename;
    bool log_rotate;
};

class RecWriter : public RecBase {
public:
    RecWriter() : RecBase() {}
    virtual ~RecWriter();
    void startRec(bool exit_if_failure);
    void record(const std::string& val);
    void logfileReopen();

private:
    std::ofstream record_ofs;
    std::string fname;
};

class SwSSRec : public RecWriter {
public:
    SwSSRec();
};

/* Record Handler for Response Publisher Class */
class ResPubRec : public RecWriter {
public:
    ResPubRec();
};

class SaiRedisRec : public RecBase {
public:
    SaiRedisRec();
};

/* Interface to access recorder classes */
class Recorder {
public:
    static const std::string DEFAULT_DIR;
    static const std::string REC_START;
    static const std::string SWSS_FNAME;
    static const std::string SAIREDIS_FNAME;
    static const std::string RESPPUB_FNAME;
    
    static std::unique_ptr<SwSSRec> swss;
    static std::unique_ptr<SaiRedisRec> sairedis;
    static std::unique_ptr<ResPubRec> respub;
};

}