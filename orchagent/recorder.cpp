#include "recorder.h"
#include "logger.h"
#include <errno.h>

using namespace swss;

const std::string Recorder::DEFAULT_DIR = ".";
const std::string Recorder::REC_START = "|recording started";
const std::string Recorder::SWSS_FNAME = "swss.rec";
const std::string Recorder::SAIREDIS_FNAME = "sairedis.rec";
const std::string Recorder::RESPPUB_FNAME = "responsepublisher.rec";


SwSSRec::SwSSRec() 
{
    /* Set Default values */
    setRecord(true);
    setRotate(false);
    setLocation(Recorder::DEFAULT_DIR);
    setFileName(Recorder::SWSS_FNAME);
}


ResPubRec::ResPubRec() 
{
    /* Set Default values */
    setRecord(false);
    setRotate(false);
    setLocation(Recorder::DEFAULT_DIR);
    setFileName(Recorder::RESPPUB_FNAME);
}


SaiRedisRec::SaiRedisRec() 
{
    /* Set Default values */
    setRecord(true);
    setRotate(false);
    setLocation(Recorder::DEFAULT_DIR);
    setFileName(Recorder::SAIREDIS_FNAME);
}


void RecWriter::startRec(bool exit_if_failure)
{
    if (!isRecord())
    {
        return ;
    }

    if (record_ofs.is_open())
    {
        SWSS_LOG_ERROR("Record File %s is already open", fname.c_str());      
    }

    fname = getLoc() + "/" + getFile();
    record_ofs.open(fname, std::ofstream::out | std::ofstream::app);
    if (!record_ofs.is_open())
    {
        SWSS_LOG_ERROR("Failed to open recording file %s: %s", fname.c_str(), strerror(errno));
        if (exit_if_failure)
        {
            exit(EXIT_FAILURE);
        }
        else
        {
            setRecord(false);
        }
    }
    record_ofs << getTimestamp() << Recorder::REC_START << std::endl;
}


RecWriter::~RecWriter()
{
    if (record_ofs.is_open())
    {
        record_ofs.close();      
    }
}


void RecWriter::record(const std::string& val)
{
    record_ofs << getTimestamp() << "|" << val << std::endl;
    if (isRotate())
    {
        setRotate(false);
        logfileReopen();
    }
}


void RecWriter::logfileReopen()
{
    if (!isRecord())
    {
        return ;
    }

    record_ofs.close();

    /*
     * On log rotate we will use the same file name, we are assuming that
     * logrotate daemon move filename to filename.1 and we will create new
     * empty file here.
     */

    record_ofs.open(fname, std::ofstream::out | std::ofstream::app);

    if (!record_ofs.is_open())
    {
        SWSS_LOG_ERROR("Failed to open recording file %s: %s", fname.c_str(), strerror(errno));
        return;
    }
}