#include "gtest/gtest.h"
#include "producerstatetable.h"
#include "../mock_table.h"
#define private public 
#include "linksync.h"
#undef private

struct if_nameindex *if_ni_mock = NULL;

/* Mock if_nameindex() call */
extern "C" {
    struct if_nameindex *__wrap_if_nameindex()
    {
        return if_ni_mock;
    }
}

extern std::string mockCmdStdcout;
extern std::vector<std::string> mockCallArgs;
extern std::set<std::string> g_portSet;
/*
Test Fixture 
*/
namespace portsyncd_ut
{
    struct PortSyncdTest : public ::testing::Test
    {   
        std::shared_ptr<swss::DBConnector> m_config_db;
        std::shared_ptr<swss::DBConnector> m_app_db;
        std::shared_ptr<swss::DBConnector> m_state_db;
        std::shared_ptr<swss::Table> m_portCfgTable;
        std::shared_ptr<swss::Table> m_portAppTable;

        virtual void SetUp() override
        {   
            testing_db::reset();

            m_config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
            m_app_db = std::make_shared<swss::DBConnector>("APPL_DB", 0);
            m_state_db = std::make_shared<swss::DBConnector>("STATE_DB", 0);
            m_portCfgTable = std::make_shared<swss::Table>(m_config_db.get(), CFG_PORT_TABLE_NAME);
            m_portAppTable = std::make_shared<swss::Table>(m_app_db.get(), APP_PORT_TABLE_NAME);
            
            /* Construct a mock if_nameindex array */
            if_ni_mock = (struct if_nameindex*) calloc(3, sizeof(struct if_nameindex));

            if_ni_mock[2].if_index = 0;
            if_ni_mock[2].if_name = NULL;

            if_ni_mock[1].if_index = 16222;
            if_ni_mock[1].if_name = "eth0";

            if_ni_mock[0].if_index = 1;
            if_ni_mock[0].if_name = "lo";
        }

        virtual void TearDown() override {
            free(if_ni_mock);
            if_ni_mock = NULL;
        }    
    };

    /* Helper Methods */
    void populateCfgDb(swss::Table* tbl){
        /* populate config db with Eth0 and Eth4 objects */
        std::vector<swss::FieldValueTuple> vec;
        vec.emplace_back("admin_status", "down"); 
        vec.emplace_back("index", "2");
        vec.emplace_back("lanes", "4,5,6,7");
        vec.emplace_back("mtu", "9100");
        vec.emplace_back("speed", "10000");
        vec.emplace_back("alias", "etp1");
        tbl->set("Ethernet0", vec);
        vec.pop_back();
        vec.emplace_back("alias", "etp1");
        tbl->set("Ethernet4", vec);
    }
}

namespace portsyncd_ut
{
    TEST_F(PortSyncdTest, test_linkSyncInit)
    {   
        mockCmdStdcout = "up\n";
        swss::LinkSync sync(m_app_db.get(), m_state_db.get());
        std::vector<std::string> keys;
        sync.m_stateMgmtPortTable.getKeys(keys);
        ASSERT_EQ(keys.size(), 1);
        ASSERT_EQ(keys.back(), "eth0");
        ASSERT_EQ(mockCallArgs.back(), "cat /sys/class/net/\"eth0\"/operstate");
    }
    
    TEST_F(PortSyncdTest, test_handlePortConfigFromConfigDB)
    {   
        swss::ProducerStateTable p(m_app_db.get(), APP_PORT_TABLE_NAME);
        populateCfgDb(m_portCfgTable.get());
        swss::DBConnector cfg_db_conn("CONFIG_DB", 0);
        handlePortConfigFromConfigDB(p, cfg_db_conn, false);
        ASSERT_EQ(g_portSet.size(), 2);
        ASSERT_NE(g_portSet.find("Ethernet0"), g_portSet.end());
        ASSERT_NE(g_portSet.find("Ethernet4"), g_portSet.end());
        std::vector<std::string> keys_to_app_db;
        m_portAppTable->getKeys(keys_to_app_db);
        ASSERT_EQ(keys_to_app_db.size(), 3);
        std::sort(keys_to_app_db.begin(), keys_to_app_db.end());
        ASSERT_EQ(keys_to_app_db[0], "Ethernet0");
        ASSERT_EQ(keys_to_app_db[1], "Ethernet4");
        ASSERT_EQ(keys_to_app_db[2], "PortConfigDone");
        std::string count;
        ASSERT_EQ(m_portAppTable->hget("PortConfigDone", "count", count), true);
        ASSERT_EQ(count, "2");
    }

    TEST_F(PortSyncdTest, test_handlePortConfigFromConfigDBWarmBoot)
    {   
        swss::ProducerStateTable p(m_app_db.get(), APP_PORT_TABLE_NAME);
        populateCfgDb(m_portCfgTable.get());
        swss::DBConnector cfg_db_conn("CONFIG_DB", 0);
        handlePortConfigFromConfigDB(p, cfg_db_conn, true);
        ASSERT_EQ(g_portSet.size(), 2);
        ASSERT_NE(g_portSet.find("Ethernet0"), g_portSet.end());
        ASSERT_NE(g_portSet.find("Ethernet4"), g_portSet.end());
        std::vector<std::string> keys_to_app_db;
        m_portAppTable->getKeys(keys_to_app_db);
        ASSERT_EQ(keys_to_app_db.size(), 0);
    }
}