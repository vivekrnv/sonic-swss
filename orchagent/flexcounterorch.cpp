#include <unordered_map>
#include "portsorch.h"
#include "fabricportsorch.h"
#include "select.h"
#include "notifier.h"
#include "sai_serialize.h"
#include "pfcwdorch.h"
#include "bufferorch.h"
#include "flexcounterorch.h"
#include "debugcounterorch.h"
#include "directory.h"
#include "copporch.h"
#include <swss/tokenize.h>
#include "routeorch.h"
#include "macsecorch.h"
#include "dash/dashorch.h"
#include "dash/dashmeterorch.h"
#include "flowcounterrouteorch.h"
#include "warm_restart.h"

extern sai_port_api_t *sai_port_api;
extern sai_switch_api_t *sai_switch_api;

extern PortsOrch *gPortsOrch;
extern FabricPortsOrch *gFabricPortsOrch;
extern IntfsOrch *gIntfsOrch;
extern BufferOrch *gBufferOrch;
extern Directory<Orch*> gDirectory;
extern CoppOrch *gCoppOrch;
extern FlowCounterRouteOrch *gFlowCounterRouteOrch;
extern Srv6Orch *gSrv6Orch;
extern sai_object_id_t gSwitchId;

#define FLEX_COUNTER_DELAY_SEC 60

#define BUFFER_POOL_WATERMARK_KEY   "BUFFER_POOL_WATERMARK"
#define PORT_KEY                    "PORT"
#define PORT_BUFFER_DROP_KEY        "PORT_BUFFER_DROP"
#define QUEUE_KEY                   "QUEUE"
#define QUEUE_WATERMARK             "QUEUE_WATERMARK"
#define PG_WATERMARK_KEY            "PG_WATERMARK"
#define PG_DROP_KEY                 "PG_DROP"
#define RIF_KEY                     "RIF"
#define ACL_KEY                     "ACL"
#define TUNNEL_KEY                  "TUNNEL"
#define FLOW_CNT_TRAP_KEY           "FLOW_CNT_TRAP"
#define FLOW_CNT_ROUTE_KEY          "FLOW_CNT_ROUTE"
#define ENI_KEY                     "ENI"
#define DASH_METER_KEY              "DASH_METER"
#define WRED_QUEUE_KEY              "WRED_ECN_QUEUE"
#define WRED_PORT_KEY               "WRED_ECN_PORT"
#define SRV6_KEY                    "SRV6"

unordered_map<string, string> flexCounterGroupMap =
{
    {"PORT", PORT_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"PORT_RATES", PORT_RATE_COUNTER_FLEX_COUNTER_GROUP},
    {"PORT_BUFFER_DROP", PORT_BUFFER_DROP_STAT_FLEX_COUNTER_GROUP},
    {"QUEUE", QUEUE_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"PFCWD", PFC_WD_FLEX_COUNTER_GROUP},
    {"QUEUE_WATERMARK", QUEUE_WATERMARK_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"PG_WATERMARK", PG_WATERMARK_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"PG_DROP", PG_DROP_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {BUFFER_POOL_WATERMARK_KEY, BUFFER_POOL_WATERMARK_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"RIF", RIF_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"RIF_RATES", RIF_RATE_COUNTER_FLEX_COUNTER_GROUP},
    {"DEBUG_COUNTER", DEBUG_COUNTER_FLEX_COUNTER_GROUP},
    {"ACL", ACL_COUNTER_FLEX_COUNTER_GROUP},
    {"TUNNEL", TUNNEL_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {FLOW_CNT_TRAP_KEY, HOSTIF_TRAP_COUNTER_FLEX_COUNTER_GROUP},
    {FLOW_CNT_ROUTE_KEY, ROUTE_FLOW_COUNTER_FLEX_COUNTER_GROUP},
    {"MACSEC_SA", COUNTERS_MACSEC_SA_GROUP},
    {"MACSEC_SA_ATTR", COUNTERS_MACSEC_SA_ATTR_GROUP},
    {"MACSEC_FLOW", COUNTERS_MACSEC_FLOW_GROUP},
    {"ENI", ENI_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"DASH_METER", METER_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"WRED_ECN_PORT", WRED_PORT_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {"WRED_ECN_QUEUE", WRED_QUEUE_STAT_COUNTER_FLEX_COUNTER_GROUP},
    {SRV6_KEY, SRV6_STAT_COUNTER_FLEX_COUNTER_GROUP},
};


FlexCounterOrch::FlexCounterOrch(DBConnector *db, vector<string> &tableNames):
    Orch(db, tableNames),
    m_bufferQueueConfigTable(db, CFG_BUFFER_QUEUE_TABLE_NAME),
    m_bufferPgConfigTable(db, CFG_BUFFER_PG_TABLE_NAME),
    m_deviceMetadataConfigTable(db, CFG_DEVICE_METADATA_TABLE_NAME)
{
    SWSS_LOG_ENTER();
    m_delayTimer = std::make_unique<SelectableTimer>(timespec{.tv_sec = FLEX_COUNTER_DELAY_SEC, .tv_nsec = 0});
    if (WarmStart::isWarmStart())
    {
        m_delayExecutor = std::make_unique<ExecutableTimer>(m_delayTimer.get(), this, "FLEX_COUNTER_DELAY");
        Orch::addExecutor(m_delayExecutor.get());
        m_delayTimer->start();
    }
    else
    {
        m_delayTimerExpired = true;
    }
}

FlexCounterOrch::~FlexCounterOrch(void)
{
    SWSS_LOG_ENTER();
}

void FlexCounterOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (!m_delayTimerExpired)
    {
        return;
    }

    VxlanTunnelOrch* vxlan_tunnel_orch = gDirectory.get<VxlanTunnelOrch*>();
    DashOrch* dash_orch = gDirectory.get<DashOrch*>();
    DashMeterOrch* dash_meter_orch = gDirectory.get<DashMeterOrch*>();
    if (gPortsOrch && !gPortsOrch->allPortsReady())
    {
        return;
    }

    if (gFabricPortsOrch && !gFabricPortsOrch->allPortsReady())
    {
        return;
    }

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        string key =  kfvKey(t);
        string op = kfvOp(t);
        auto data = kfvFieldsValues(t);

        if (!flexCounterGroupMap.count(key))
        {
            SWSS_LOG_NOTICE("Invalid flex counter group input, %s", key.c_str());
            consumer.m_toSync.erase(it++);
            continue;
        }

        if (op == SET_COMMAND)
        {
            string bulk_chunk_size;
            string bulk_chunk_size_per_counter;

            for (auto valuePair:data)
            {
                const auto &field = fvField(valuePair);
                const auto &value = fvValue(valuePair);

                if (field == POLL_INTERVAL_FIELD)
                {
                    setFlexCounterGroupPollInterval(flexCounterGroupMap[key], value);

                    if (gPortsOrch && gPortsOrch->isGearboxEnabled())
                    {
                        if (key == PORT_KEY || key.rfind("MACSEC", 0) == 0)
                        {
                            setFlexCounterGroupPollInterval(flexCounterGroupMap[key], value, true);
                        }
                    }
                }
                else if (field == BULK_CHUNK_SIZE_FIELD)
                {
                    bulk_chunk_size = value;
                }
                else if (field == BULK_CHUNK_SIZE_PER_PREFIX_FIELD)
                {
                    bulk_chunk_size_per_counter = value;
                }
                else if(field == FLEX_COUNTER_STATUS_FIELD)
                {
                    // Currently, the counters are disabled for polling by default
                    // The queue maps will be generated as soon as counters are enabled for polling
                    // Counter polling is enabled by pushing the COUNTER_ID_LIST/ATTR_ID_LIST, which contains
                    // the list of SAI stats/attributes of polling interest, to the FLEX_COUNTER_DB under the
                    // additional condition that the polling interval at that time is set nonzero positive,
                    // which is automatically satisfied upon the creation of the orch object that requires
                    // the syncd flex counter polling service
                    // This postponement is introduced by design to accelerate the initialization process
                    if(gPortsOrch && (value == "enable"))
                    {
                        if(key == PORT_KEY)
                        {
                            gPortsOrch->generatePortCounterMap();
                            m_port_counter_enabled = true;
                        }
                        else if(key == PORT_BUFFER_DROP_KEY)
                        {
                            gPortsOrch->generatePortBufferDropCounterMap();
                            m_port_buffer_drop_counter_enabled = true;
                        }
                        else if(key == QUEUE_KEY)
                        {
                            gPortsOrch->generateQueueMap(getQueueConfigurations());
                            m_queue_enabled = true;
                            gPortsOrch->addQueueFlexCounters(getQueueConfigurations());
                        }
                        else if(key == QUEUE_WATERMARK)
                        {
                            gPortsOrch->generateQueueMap(getQueueConfigurations());
                            m_queue_watermark_enabled = true;
                            gPortsOrch->addQueueWatermarkFlexCounters(getQueueConfigurations());
                        }
                        else if(key == PG_DROP_KEY)
                        {
                            gPortsOrch->generatePriorityGroupMap(getPgConfigurations());
                            m_pg_enabled = true;
                            gPortsOrch->addPriorityGroupFlexCounters(getPgConfigurations());
                        }
                        else if(key == PG_WATERMARK_KEY)
                        {
                            gPortsOrch->generatePriorityGroupMap(getPgConfigurations());
                            m_pg_watermark_enabled = true;
                            gPortsOrch->addPriorityGroupWatermarkFlexCounters(getPgConfigurations());
                        }
			else if(key == WRED_PORT_KEY)
			{
                            gPortsOrch->generateWredPortCounterMap();
                            m_wred_port_counter_enabled = true;
			}
			else if(key == WRED_QUEUE_KEY)
			{
                            gPortsOrch->generateQueueMap(getQueueConfigurations());
                            m_wred_queue_counter_enabled = true;
                            gPortsOrch->addWredQueueFlexCounters(getQueueConfigurations());
			}
                    }
                    if(gIntfsOrch && (key == RIF_KEY) && (value == "enable"))
                    {
                        gIntfsOrch->generateInterfaceMap();
                    }
                    if (gBufferOrch && (key == BUFFER_POOL_WATERMARK_KEY) && (value == "enable"))
                    {
                        gBufferOrch->generateBufferPoolWatermarkCounterIdList();
                    }
                    if (gFabricPortsOrch)
                    {
                        gFabricPortsOrch->generateQueueStats();
                    }
                    if (vxlan_tunnel_orch && (key== TUNNEL_KEY) && (value == "enable"))
                    {
                        vxlan_tunnel_orch->generateTunnelCounterMap();
                    }
                    if (dash_orch && (key == ENI_KEY))
                    {
                        dash_orch->handleFCStatusUpdate((value == "enable"));
                    }
                    if (dash_meter_orch && (key == DASH_METER_KEY))
                    {
                        dash_meter_orch->handleMeterFCStatusUpdate((value == "enable"));
                    }
                    if (gCoppOrch && (key == FLOW_CNT_TRAP_KEY))
                    {
                        if (value == "enable")
                        {
                            m_hostif_trap_counter_enabled = true;
                            gCoppOrch->generateHostIfTrapCounterIdList();
                        }
                        else if (value == "disable")
                        {
                            gCoppOrch->clearHostIfTrapCounterIdList();
                            m_hostif_trap_counter_enabled = false;
                        }
                    }
                    if (gFlowCounterRouteOrch && gFlowCounterRouteOrch->getRouteFlowCounterSupported() && key == FLOW_CNT_ROUTE_KEY)
                    {
                        if (value == "enable" && !m_route_flow_counter_enabled)
                        {
                            m_route_flow_counter_enabled = true;
                            gFlowCounterRouteOrch->generateRouteFlowStats();
                        }
                        else if (value == "disable" && m_route_flow_counter_enabled)
                        {
                            gFlowCounterRouteOrch->clearRouteFlowStats();
                            m_route_flow_counter_enabled = false;
                        }
                    }
                    if (gSrv6Orch && (key == SRV6_KEY))
                    {
                        gSrv6Orch->setCountersState((value == "enable"));
                    }

                    if (gPortsOrch)
                    {
                        gPortsOrch->flushCounters();
                    }

                    setFlexCounterGroupOperation(flexCounterGroupMap[key], value);

                    if (gPortsOrch && gPortsOrch->isGearboxEnabled())
                    {
                        if (key == PORT_KEY || key.rfind("MACSEC", 0) == 0)
                        {
                            setFlexCounterGroupOperation(flexCounterGroupMap[key], value, true);
                        }
                    }
                }
                else
                {
                    SWSS_LOG_NOTICE("Unsupported field %s", field.c_str());
                }
            }

            if (!bulk_chunk_size.empty() || !bulk_chunk_size_per_counter.empty())
            {
                m_groupsWithBulkChunkSize.insert(key);
                setFlexCounterGroupBulkChunkSize(flexCounterGroupMap[key],
                                                 bulk_chunk_size.empty() ? "NULL" : bulk_chunk_size,
                                                 bulk_chunk_size_per_counter.empty() ? "NULL" : bulk_chunk_size_per_counter);
            }
            else if (m_groupsWithBulkChunkSize.find(key) != m_groupsWithBulkChunkSize.end())
            {
                setFlexCounterGroupBulkChunkSize(flexCounterGroupMap[key], "NULL", "NULL");
                m_groupsWithBulkChunkSize.erase(key);
            }
        }

        consumer.m_toSync.erase(it++);
    }
}

void FlexCounterOrch::doTask(SelectableTimer&)
{
    SWSS_LOG_ENTER();

    if (m_delayTimerExpired)
    {
        return;
    }

    SWSS_LOG_NOTICE("Processing counters");
    m_delayTimer->stop();
    m_delayTimerExpired = true;
}

bool FlexCounterOrch::getPortCountersState() const
{
    return m_port_counter_enabled;
}

bool FlexCounterOrch::getPortBufferDropCountersState() const
{
    return m_port_buffer_drop_counter_enabled;
}

bool FlexCounterOrch::getQueueCountersState() const
{
    return m_queue_enabled;
}

bool FlexCounterOrch::getQueueWatermarkCountersState() const
{
    return m_queue_watermark_enabled;
}

bool FlexCounterOrch::getPgCountersState() const
{
    return m_pg_enabled;
}

bool FlexCounterOrch::getPgWatermarkCountersState() const
{
    return m_pg_watermark_enabled;
}

bool FlexCounterOrch::getWredQueueCountersState() const
{
    return m_wred_queue_counter_enabled;
}

bool FlexCounterOrch::getWredPortCountersState() const
{
    return m_wred_port_counter_enabled;
}

bool FlexCounterOrch::bake()
{
    /*
     * bake is called during warmreboot reconciling procedure.
     * By default, it should fetch items from the tables the sub agents listen to,
     * and then push them into m_toSync of each sub agent.
     * The motivation is to make sub agents handle the saved entries first and then handle the upcoming entries.
     * The FCs are not data plane configuration required during reconciling process, hence don't do anything in bake.
     */

    return true;
}

static bool isCreateOnlyConfigDbBuffers(Table& deviceMetadataConfigTable)
{
    std::string createOnlyConfigDbBuffersValue;

    try
    {
        if (deviceMetadataConfigTable.hget("localhost", "create_only_config_db_buffers", createOnlyConfigDbBuffersValue))
        {
            if (createOnlyConfigDbBuffersValue == "true")
            {
                return true;
            }
        }
    }
    catch(const std::system_error& e)
    {
        SWSS_LOG_ERROR("System error: %s", e.what());
    }

    return false;
}

map<string, FlexCounterQueueStates> FlexCounterOrch::getQueueConfigurations()
{
    SWSS_LOG_ENTER();

    map<string, FlexCounterQueueStates> queuesStateVector;

    if (!isCreateOnlyConfigDbBuffers(m_deviceMetadataConfigTable))
    {
        FlexCounterQueueStates flexCounterQueueState(0);
        queuesStateVector.insert(make_pair(createAllAvailableBuffersStr, flexCounterQueueState));
        return queuesStateVector;
    }

    std::vector<std::string> portQueueKeys;
    gBufferOrch->getBufferObjectsWithNonZeroProfile(portQueueKeys, APP_BUFFER_QUEUE_TABLE_NAME);

    for (const auto& portQueueKey : portQueueKeys)
    {
        auto toks = tokenize(portQueueKey, ':');
        if (toks.size() != 2)
        {
            SWSS_LOG_ERROR("Invalid BUFFER_QUEUE key: [%s]", portQueueKey.c_str());
            continue;
        }

        auto configPortNames = tokenize(toks[0], ',');
        auto configPortQueues = toks[1];
        toks = tokenize(configPortQueues, '-');

        for (const auto& configPortName : configPortNames)
        {
            uint32_t maxQueueNumber = gPortsOrch->getNumberOfPortSupportedQueueCounters(configPortName);
            uint32_t maxQueueIndex = maxQueueNumber - 1;
            uint32_t minQueueIndex = 0;

            if (!queuesStateVector.count(configPortName))
            {
                FlexCounterQueueStates flexCounterQueueState(maxQueueNumber);
                queuesStateVector.insert(make_pair(configPortName, flexCounterQueueState));
            }

            try {
                auto startIndex = to_uint<uint32_t>(toks[0], minQueueIndex, maxQueueIndex);
                if (toks.size() > 1)
                {
                    auto endIndex = to_uint<uint32_t>(toks[1], minQueueIndex, maxQueueIndex);
                    queuesStateVector.at(configPortName).enableQueueCounters(startIndex, endIndex);
                }
                else
                {
                    queuesStateVector.at(configPortName).enableQueueCounter(startIndex);
                }

                Port port;
                gPortsOrch->getPort(configPortName, port);
                if (port.m_host_tx_queue_configured && port.m_host_tx_queue <= maxQueueIndex)
                {
                    queuesStateVector.at(configPortName).enableQueueCounter(port.m_host_tx_queue);
                }
            } catch (std::invalid_argument const& e) {
                    SWSS_LOG_ERROR("Invalid queue index [%s] for port [%s]", configPortQueues.c_str(), configPortName.c_str());
                    continue;
            }
        }
    }

    return queuesStateVector;
}

map<string, FlexCounterPgStates> FlexCounterOrch::getPgConfigurations()
{
    SWSS_LOG_ENTER();

    map<string, FlexCounterPgStates> pgsStateVector;

    if (!isCreateOnlyConfigDbBuffers(m_deviceMetadataConfigTable))
    {
        FlexCounterPgStates flexCounterPgState(0);
        pgsStateVector.insert(make_pair(createAllAvailableBuffersStr, flexCounterPgState));
        return pgsStateVector;
    }

    std::vector<std::string> portPgKeys;
    gBufferOrch->getBufferObjectsWithNonZeroProfile(portPgKeys, APP_BUFFER_PG_TABLE_NAME);

    for (const auto& portPgKey : portPgKeys)
    {
        auto toks = tokenize(portPgKey, ':');
        if (toks.size() != 2)
        {
            SWSS_LOG_ERROR("Invalid BUFFER_PG key: [%s]", portPgKey.c_str());
            continue;
        }

        auto configPortNames = tokenize(toks[0], ',');
        auto configPortPgs = toks[1];
        toks = tokenize(configPortPgs, '-');

        for (const auto& configPortName : configPortNames)
        {
            uint32_t maxPgNumber = gPortsOrch->getNumberOfPortSupportedPgCounters(configPortName);
            uint32_t maxPgIndex = maxPgNumber - 1;
            uint32_t minPgIndex = 0;

            if (!pgsStateVector.count(configPortName))
            {
                FlexCounterPgStates flexCounterPgState(maxPgNumber);
                pgsStateVector.insert(make_pair(configPortName, flexCounterPgState));
            }

            try {
                auto startIndex = to_uint<uint32_t>(toks[0], minPgIndex, maxPgIndex);
                if (toks.size() > 1)
                {
                    auto endIndex = to_uint<uint32_t>(toks[1], minPgIndex, maxPgIndex);
                    pgsStateVector.at(configPortName).enablePgCounters(startIndex, endIndex);
                }
                else
                {
                    pgsStateVector.at(configPortName).enablePgCounter(startIndex);
                }
            } catch (std::invalid_argument const& e) {
                    SWSS_LOG_ERROR("Invalid pg index [%s] for port [%s]", configPortPgs.c_str(), configPortName.c_str());
                    continue;
            }
        }
    }

    return pgsStateVector;
}

FlexCounterQueueStates::FlexCounterQueueStates(uint32_t maxQueueNumber)
{
    SWSS_LOG_ENTER();
    m_queueStates.resize(maxQueueNumber, false);
}

bool FlexCounterQueueStates::isQueueCounterEnabled(uint32_t index) const
{
    SWSS_LOG_ENTER();
    return m_queueStates[index];
}

void FlexCounterQueueStates::enableQueueCounters(uint32_t startIndex, uint32_t endIndex)
{
    SWSS_LOG_ENTER();
    for (uint32_t queueIndex = startIndex; queueIndex <= endIndex; queueIndex++)
    {
        enableQueueCounter(queueIndex);
    }
}

void FlexCounterQueueStates::enableQueueCounter(uint32_t queueIndex)
{
    SWSS_LOG_ENTER();
    m_queueStates[queueIndex] = true;
}

FlexCounterPgStates::FlexCounterPgStates(uint32_t maxPgNumber)
{
    SWSS_LOG_ENTER();
    m_pgStates.resize(maxPgNumber, false);
}

bool FlexCounterPgStates::isPgCounterEnabled(uint32_t index) const
{
    SWSS_LOG_ENTER();
    return m_pgStates[index];
}

void FlexCounterPgStates::enablePgCounters(uint32_t startIndex, uint32_t endIndex)
{
    SWSS_LOG_ENTER();
    for (uint32_t pgIndex = startIndex; pgIndex <= endIndex; pgIndex++)
    {
        enablePgCounter(pgIndex);
    }
}

void FlexCounterPgStates::enablePgCounter(uint32_t pgIndex)
{
    SWSS_LOG_ENTER();
    m_pgStates[pgIndex] = true;
}
