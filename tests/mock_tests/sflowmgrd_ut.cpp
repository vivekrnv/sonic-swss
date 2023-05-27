#include "gtest/gtest.h"
#include "mock_table.h"
#include "redisutility.h"
#include "sflowmgr.h"

namespace sflowmgr_ut
{
    using namespace swss;
    using namespace std;

    struct SflowMgrTest : public ::testing::Test
    {
        shared_ptr<swss::DBConnector> m_app_db;
        shared_ptr<swss::DBConnector> m_config_db;
        shared_ptr<swss::DBConnector> m_state_db;
        shared_ptr<SflowMgr> m_sflowMgr;
        SflowMgrTest()
        {
            m_app_db = make_shared<swss::DBConnector>(
                "APPL_DB", 0);
            m_config_db = make_shared<swss::DBConnector>(
                "CONFIG_DB", 0);
            m_state_db = make_shared<swss::DBConnector>(
                "STATE_DB", 0);
        }

        virtual void SetUp() override
        {
            ::testing_db::reset();
            TableConnector conf_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
            TableConnector state_port_table(m_state_db.get(), STATE_PORT_TABLE_NAME);
            TableConnector conf_sflow_table(m_config_db.get(), CFG_SFLOW_TABLE_NAME);
            TableConnector conf_sflow_session_table(m_config_db.get(), CFG_SFLOW_SESSION_TABLE_NAME);

            vector<TableConnector> sflow_tables = {
                conf_port_table,
                state_port_table,
                conf_sflow_table,
                conf_sflow_session_table
            };
            m_sflowMgr.reset(new SflowMgr(m_app_db.get(), sflow_tables));
            enableSflow();
        }

        void enableSflow()
        {
            Table cfg_sflow(m_config_db.get(), CFG_SFLOW_TABLE_NAME);
            cfg_sflow.set("global", {
                {"admin_state", "up"}
            });
            m_sflowMgr->addExistingData(&cfg_sflow);
            m_sflowMgr->doTask();
        }
    };

    TEST_F(SflowMgrTest, test_RateConfiguration)
    {
        Table state_port_table(m_state_db.get(), STATE_PORT_TABLE_NAME);
        Table appl_sflow_table(m_app_db.get(), APP_SFLOW_SESSION_TABLE_NAME);
        Table cfg_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);

        cfg_port_table.set("Ethernet0", {
            {"speed", "100000"},
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->doTask();
    
        std::vector<FieldValueTuple> values;
        appl_sflow_table.get("Ethernet0", values);
        auto value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        ASSERT_TRUE(value_rate.get() == "100000");

        /* Scenario: Operational Speed Changes to 25000 */
        state_port_table.set("Ethernet0", {
            {"speed", "25000"}
        });

        m_sflowMgr->addExistingData(&state_port_table);
        m_sflowMgr->doTask();

        values.clear();
        appl_sflow_table.get("Ethernet0", values);
        value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        ASSERT_TRUE(value_rate.get() == "25000");
    }

    TEST_F(SflowMgrTest, test_RateConfigurationOperUpDown)
    {
        /* Simulates a realistic scenario of oper up down events mixed with auto neg */
        Table state_port_table(m_state_db.get(), STATE_PORT_TABLE_NAME);
        Table appl_sflow_table(m_app_db.get(), APP_SFLOW_SESSION_TABLE_NAME);
        Table cfg_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        std::vector<FieldValueTuple> values;

        /* Configure the Speed to 100G */
        cfg_port_table.set("Ethernet0", {
            {"speed", "100000"},
        });

        /* Scenario: Operational Speed Changes to 100G with autoneg */
        state_port_table.set("Ethernet0", {
            {"speed", "100000"}
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->addExistingData(&state_port_table);
        m_sflowMgr->doTask();

        /* User changes the config speed to 10G */
        cfg_port_table.set("Ethernet0", {
            {"speed", "10000"},
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->doTask();

        values.clear();
        appl_sflow_table.get("Ethernet0", values);
        auto value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        /* Rate Should still adhere to oper_speed */
        ASSERT_TRUE(value_rate.get() == "100000");

        /* Scenario: Operational Speed Changes to 10G, with autoneg */
        state_port_table.set("Ethernet0", {
            {"speed", "10000"}
        });

        m_sflowMgr->addExistingData(&state_port_table);
        m_sflowMgr->doTask();

        values.clear();
        appl_sflow_table.get("Ethernet0", values);
        value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        /* Rate is supposed to be updated */
        ASSERT_TRUE(value_rate.get() == "10000");

        /* Configured speed is updated by user */
        cfg_port_table.set("Ethernet0", {
            {"speed", "200000"},
        });

        m_sflowMgr->addExistingData(&state_port_table);
        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->doTask();

        values.clear();
        appl_sflow_table.get("Ethernet0", values);
        value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        /* Sampling Rate will not be updated */
        ASSERT_TRUE(value_rate.get() == "10000");
    }

    TEST_F(SflowMgrTest, test_OnlyStateDbNotif)
    {
        Table state_port_table(m_state_db.get(), STATE_PORT_TABLE_NAME);
        Table appl_sflow_table(m_app_db.get(), APP_SFLOW_SESSION_TABLE_NAME);
        Table cfg_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);

        state_port_table.set("Ethernet0", {
            {"speed", "100000"}
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->doTask();
    
        std::vector<FieldValueTuple> values;
        appl_sflow_table.get("Ethernet0", values);
        auto value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_FALSE(value_rate);
    }

    TEST_F(SflowMgrTest, test_LocalRateConfiguration)
    {
        Table appl_sflow_table(m_app_db.get(), APP_SFLOW_SESSION_TABLE_NAME);
        Table cfg_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        Table cfg_sflow_table(m_config_db.get(), CFG_SFLOW_SESSION_TABLE_NAME);

        cfg_port_table.set("Ethernet0", {
            {"speed", "100000"}
        });

        cfg_sflow_table.set("Ethernet0", {
            {"sample_rate", "12345"}
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->addExistingData(&cfg_sflow_table);
        m_sflowMgr->doTask();

        std::vector<FieldValueTuple> values;
        appl_sflow_table.get("Ethernet0", values);
        auto value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        ASSERT_TRUE(value_rate.get() == "12345");
    }

    TEST_F(SflowMgrTest, test_LocalRateConfWithOperSpeed)
    {
        Table state_port_table(m_state_db.get(), STATE_PORT_TABLE_NAME);
        Table appl_sflow_table(m_app_db.get(), APP_SFLOW_SESSION_TABLE_NAME);
        Table cfg_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        Table cfg_sflow_table(m_config_db.get(), CFG_SFLOW_SESSION_TABLE_NAME);

        cfg_port_table.set("Ethernet0", {
            {"speed", "100000"},
        });

        /* Scenario: Operational Speed Changes to 25000 */
        state_port_table.set("Ethernet0", {
            {"speed", "25000"},
            {"netdev_oper_status", "up"}
        });

        cfg_sflow_table.set("Ethernet0", {
            {"sample_rate", "12345"}
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->addExistingData(&cfg_sflow_table);
        m_sflowMgr->addExistingData(&state_port_table);
        m_sflowMgr->doTask();

        std::vector<FieldValueTuple> values;
        appl_sflow_table.get("Ethernet0", values);
        auto value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        ASSERT_TRUE(value_rate.get() == "12345");

        /* Operational Speed Changes again to 50000 */
        state_port_table.set("Ethernet0", {
            {"speed", "50000"}
        });

        m_sflowMgr->addExistingData(&state_port_table);
        m_sflowMgr->doTask();

        appl_sflow_table.get("Ethernet0", values);
        value_rate = swss::fvsGetValue(values, "sample_rate", true);
        /* Local config wouldn't change */
        ASSERT_TRUE(value_rate);
        ASSERT_TRUE(value_rate.get() == "12345");
    }

    TEST_F(SflowMgrTest, test_new_speed)
    {
        Table appl_sflow_table(m_app_db.get(), APP_SFLOW_SESSION_TABLE_NAME);
        Table cfg_port_table(m_config_db.get(), CFG_PORT_TABLE_NAME);
        Table cfg_sflow_table(m_config_db.get(), CFG_SFLOW_SESSION_TABLE_NAME);

        cfg_port_table.set("Ethernet0", {
            {"speed", "800000"}
        });

        m_sflowMgr->addExistingData(&cfg_port_table);
        m_sflowMgr->doTask();
    
        std::vector<FieldValueTuple> values;
        appl_sflow_table.get("Ethernet0", values);
        auto value_rate = swss::fvsGetValue(values, "sample_rate", true);
        ASSERT_TRUE(value_rate);
        ASSERT_TRUE(value_rate.get() == "800000");
    }
}
