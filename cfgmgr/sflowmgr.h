#pragma once

#include "dbconnector.h"
#include "orch.h"
#include "producerstatetable.h"

#include <map>
#include <set>
#include <string>

namespace swss {

#define SFLOW_ERROR_SPEED_STR "error"
#define SFLOW_NA_SPEED_STR "N/A"

struct SflowPortInfo
{
    bool        local_rate_cfg;
    bool        local_admin_cfg;
    bool        autoneg_enabled;
    std::string speed;
    std::string oper_speed;
    std::string rate;
    std::string admin;
};

/* Port to Local config map  */
typedef std::map<std::string, SflowPortInfo> SflowPortConfMap;

class SflowMgr : public Orch
{
public:
    SflowMgr(DBConnector *appDb, const std::vector<TableConnector>& tableNames);

    using Orch::doTask;
private:
    ProducerStateTable     m_appSflowTable;
    ProducerStateTable     m_appSflowSessionTable;
    SflowPortConfMap       m_sflowPortConfMap;
    bool                   m_intfAllConf;
    bool                   m_gEnable;

    void doTask(Consumer &consumer);
    void sflowHandleService(bool enable);
    void sflowUpdatePortInfo(Consumer &consumer);
    void sflowProcessOperSpeed(Consumer &consumer);
    void sflowHandleSessionAll(bool enable);
    void sflowHandleSessionLocal(bool enable);
    void sflowCheckAndFillValues(std::string alias, std::vector<FieldValueTuple> &values, std::vector<FieldValueTuple> &fvs);
    void sflowGetPortInfo(std::vector<FieldValueTuple> &fvs, SflowPortInfo &local_info);
    void sflowGetGlobalInfo(std::vector<FieldValueTuple> &fvs, const std::string& alias);
    std::string findSamplingRate(const std::string& speed);
};

}
