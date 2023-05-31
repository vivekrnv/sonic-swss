#include <fstream>
#include <iostream>
#include <mutex>
#include <unistd.h>
#include <vector>

#include "exec.h"
#include "sflowmgr.h"
#include "schema.h"
#include "select.h"

using namespace std;
using namespace swss;

/* select() function timeout retry time, in millisecond */
#define SELECT_TIMEOUT 1000

/*
 * Following global variables are defined here for the purpose of
 * using existing Orch class which is to be refactored soon to
 * eliminate the direct exposure of the global variables.
 *
 * Once Orch class refactoring is done, these global variables
 * should be removed from here.
 */
int gBatchSize = 0;
bool gSwssRecord = false;
bool gLogRotate = false;
ofstream gRecordOfs;
string gRecordFile;
bool gResponsePublisherRecord = false;
bool gResponsePublisherLogRotate = false;
ofstream gResponsePublisherRecordOfs;
string gResponsePublisherRecordFile;
/* Global database mutex */
mutex gDbMutex;

int main(int argc, char **argv)
{
    Logger::linkToDbNative("sflowmgrd");
    SWSS_LOG_ENTER();

    SWSS_LOG_NOTICE("--- Starting sflowmgrd ---");

    try
    {
        DBConnector cfgDb("CONFIG_DB", 0);
        DBConnector appDb("APPL_DB", 0);
        DBConnector stateDb("STATE_DB", 0);

        TableConnector conf_port_table(&cfgDb, CFG_PORT_TABLE_NAME);
        TableConnector state_port_table(&stateDb, STATE_PORT_TABLE_NAME);
        TableConnector conf_sflow_table(&cfgDb, CFG_SFLOW_TABLE_NAME);
        TableConnector conf_sflow_session_table(&cfgDb, CFG_SFLOW_SESSION_TABLE_NAME);

        vector<TableConnector> sflow_tables = {
            conf_port_table,
            state_port_table,
            conf_sflow_table,
            conf_sflow_session_table
        };

        SflowMgr sflowmgr(&appDb, sflow_tables);
        /* During process startup, the ordering of config_db followed by state_db notifications cannot be guaranteed 
           and so handle the cfg events manually first */
        sflowmgr.readPortConfig();

        vector<Orch *> orchList = {&sflowmgr};

        swss::Select s;
        for (Orch *o : orchList)
        {
            s.addSelectables(o->getSelectables());
        }

        while (true)
        {
            Selectable *sel;
            int ret;

            ret = s.select(&sel, SELECT_TIMEOUT);
            if (ret == Select::ERROR)
            {
                SWSS_LOG_NOTICE("Error: %s!", strerror(errno));
                continue;
            }
            if (ret == Select::TIMEOUT)
            {
                sflowmgr.doTask();
                continue;
            }

            auto *c = (Executor *)sel;
            c->execute();
        }
    }
    catch (const exception &e)
    {
        SWSS_LOG_ERROR("Runtime error: %s", e.what());
    }
    return -1;
}
