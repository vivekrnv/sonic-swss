#include "../ut_helper.h"
#include "../mock_orchagent_main.h"
#include "../mock_table.h"
#include "port.h"
#define private public // Need to modify internal cache
#include "portsorch.h"
#include "fdborch.h"
#include "crmorch.h"
#undef private

#define ETH0 "Ethernet0"
#define VLAN40 "Vlan40"

extern redisReply *mockReply;
extern CrmOrch*  gCrmOrch;

/*
Test Fixture 
*/
namespace fdb_syncd_flush_test
{
    struct FdbOrchTest : public ::testing::Test
    {   
        std::shared_ptr<swss::DBConnector> m_config_db;
        std::shared_ptr<swss::DBConnector> m_app_db;
        std::shared_ptr<swss::DBConnector> m_state_db;
        std::shared_ptr<swss::DBConnector> m_asic_db;
        std::shared_ptr<swss::DBConnector> m_chassis_app_db;
        std::shared_ptr<PortsOrch> m_portsOrch;
        std::shared_ptr<FdbOrch> m_fdborch;

        virtual void SetUp() override
        {
            map<string, string> profile = {
                { "SAI_VS_SWITCH_TYPE", "SAI_VS_SWITCH_TYPE_BCM56850" },
                { "KV_DEVICE_MAC_ADDRESS", "20:03:04:05:06:00" }
            };

            ut_helper::initSaiApi(profile);
            
            /* Create Switch */
            sai_attribute_t attr;
            attr.id = SAI_SWITCH_ATTR_INIT_SWITCH;
            attr.value.booldata = true;
            auto status = sai_switch_api->create_switch(&gSwitchId, 1, &attr);
            ASSERT_EQ(status, SAI_STATUS_SUCCESS);

            m_config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
            m_app_db = std::make_shared<swss::DBConnector>("APPL_DB", 0);
            m_state_db = make_shared<swss::DBConnector>("STATE_DB", 0);
            m_asic_db = std::make_shared<swss::DBConnector>("ASIC_DB", 0);

            // Construct dependencies
            // 1) Portsorch
            const int portsorch_base_pri = 40;

            vector<table_name_with_pri_t> ports_tables = {
                { APP_PORT_TABLE_NAME, portsorch_base_pri + 5 },
                { APP_VLAN_TABLE_NAME, portsorch_base_pri + 2 },
                { APP_VLAN_MEMBER_TABLE_NAME, portsorch_base_pri },
                { APP_LAG_TABLE_NAME, portsorch_base_pri + 4 },
                { APP_LAG_MEMBER_TABLE_NAME, portsorch_base_pri }
            };

            m_portsOrch = std::make_shared<PortsOrch>(m_app_db.get(), m_state_db.get(), ports_tables, m_chassis_app_db.get());

            // 2) Crmorch
            ASSERT_EQ(gCrmOrch, nullptr);
            gCrmOrch = new CrmOrch(m_config_db.get(), CFG_CRM_TABLE_NAME);
            
             // Construct fdborch
            vector<table_name_with_pri_t> app_fdb_tables = {
                { APP_FDB_TABLE_NAME,        FdbOrch::fdborch_pri},
                { APP_VXLAN_FDB_TABLE_NAME,  FdbOrch::fdborch_pri},
                { APP_MCLAG_FDB_TABLE_NAME,  FdbOrch::fdborch_pri}
            };

            TableConnector stateDbFdb(m_state_db.get(), STATE_FDB_TABLE_NAME);
            TableConnector stateMclagDbFdb(m_state_db.get(), STATE_MCLAG_REMOTE_FDB_TABLE_NAME);

            m_fdborch = std::make_shared<FdbOrch>(m_app_db.get(), 
                                                  app_fdb_tables, 
                                                  stateDbFdb,
                                                  stateMclagDbFdb, 
                                                  m_portsOrch.get());
        }

        virtual void TearDown() override {
            delete gCrmOrch;
            gCrmOrch = nullptr;

            ut_helper::uninitSaiApi();
        }
    };

    /* Helper Methods */
    void setUpVlan(PortsOrch* m_portsOrch){
        /* Updates portsOrch internal cache for Vlan40 */
        std::string alias = VLAN40;
        sai_object_id_t oid = 0x26000000000796;

        Port vlan(alias, Port::VLAN);
        vlan.m_vlan_info.vlan_oid = oid;
        vlan.m_vlan_info.vlan_id = 40;
        vlan.m_members = set<string>();

        m_portsOrch->m_portList[alias] = vlan;
        m_portsOrch->m_port_ref_count[alias] = 0;
        m_portsOrch->saiOidToAlias[oid] = alias;
    }

    void setUpPort(PortsOrch* m_portsOrch){
        /* Updates portsOrch internal cache for Ethernet0 */
        std::string alias = ETH0;
        sai_object_id_t oid = 0x10000000004a4;

        Port port(alias, Port::PHY);
        port.m_index = 1;
        port.m_port_id = oid;
        port.m_hif_id = 0xd00000000056e;

        m_portsOrch->m_portList[alias] = port;
        m_portsOrch->saiOidToAlias[oid] =  alias;
    }

    void setUpVlanMember(PortsOrch* m_portsOrch){
        /* Updates portsOrch internal cache for adding Ethernet0 into Vlan40 */
        sai_object_id_t bridge_port_id = 0x3a000000002c33;
        
        /* Add Bridge Port */
        m_portsOrch->m_portList[ETH0].m_bridge_port_id = bridge_port_id;
        m_portsOrch->saiOidToAlias[bridge_port_id] = ETH0;
        m_portsOrch->m_portList[VLAN40].m_members.insert(ETH0);
    }
}

namespace fdb_syncd_flush_test
{
    /* Test Consolidated Flush Per Vlan and Per Port */
    TEST_F(FdbOrchTest, ConsolidatedFlushVlanandPort)
    {   
        ASSERT_NE(m_portsOrch, nullptr);
        setUpVlan(m_portsOrch.get());
        setUpPort(m_portsOrch.get());
        ASSERT_NE(m_portsOrch->m_portList.find(VLAN40), m_portsOrch->m_portList.end());
        ASSERT_NE(m_portsOrch->m_portList.find(ETH0), m_portsOrch->m_portList.end());
        setUpVlanMember(m_portsOrch.get());

        /* Learn a dynamic FDB Entry */
        sai_fdb_event_t type = SAI_FDB_EVENT_LEARNED;
        sai_fdb_entry_t entry;
        //7c:fe:90:12:22:ec
        vector<uint8_t> mac_addr = {124, 254, 144, 18, 34, 236};
        for (int i = 0; i < (int)mac_addr.size(); i++){
            *(entry.mac_address+i) = mac_addr[i];
        }
        entry.bv_id = m_portsOrch->m_portList[VLAN40].m_vlan_info.vlan_oid;
        sai_int32_t fdb_entry_type = SAI_FDB_ENTRY_TYPE_DYNAMIC;
        sai_object_id_t bridge_port_id = m_portsOrch->m_portList[ETH0].m_bridge_port_id;

        m_fdborch->update(type, &entry, bridge_port_id, fdb_entry_type);
        
        string port;
        string entry_type;
        
        ASSERT_EQ(m_fdborch->m_fdbStateTable.hget("Vlan40:7c:fe:90:12:22:ec", "port", port), true);
        ASSERT_EQ(m_fdborch->m_fdbStateTable.hget("Vlan40:7c:fe:90:12:22:ec", "type", entry_type), true);
        
        ASSERT_EQ(port, "Ethernet0");
        ASSERT_EQ(entry_type, "dynamic");
    }
}