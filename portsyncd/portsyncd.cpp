#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include "dbconnector.h"
#include "select.h"
#include "netdispatcher.h"
#include "netlink.h"
#include "portsyncd/linksync.h"
#include "subscriberstatetable.h"
#include "warm_restart.h"

using namespace std;
using namespace swss;

#define DEFAULT_SELECT_TIMEOUT 1000 /* ms */

extern set<string> g_portSet;
extern bool g_init;

void usage()
{
    cout << "Usage: portsyncd" << endl;
    cout << "       port lane mapping is from configDB" << endl;
    cout << "       this program will exit if configDB does not contain that info" << endl;
}

int main(int argc, char **argv)
{
    Logger::linkToDbNative("portsyncd");
    int opt;

    while ((opt = getopt(argc, argv, "v:h")) != -1 )
    {
        switch (opt)
        {
        case 'h':
            usage();
            return 1;
        default: /* '?' */
            usage();
            return EXIT_FAILURE;
        }
    }

    DBConnector cfgDb("CONFIG_DB", 0);
    DBConnector appl_db("APPL_DB", 0);
    DBConnector state_db("STATE_DB", 0);
    ProducerStateTable p(&appl_db, APP_PORT_TABLE_NAME);

    WarmStart::initialize("portsyncd", "swss");
    WarmStart::checkWarmStart("portsyncd", "swss");
    const bool warm = WarmStart::isWarmStart();

    try
    {
        NetLink netlink;
        Select s;

        netlink.registerGroup(RTNLGRP_LINK);
        netlink.dumpRequest(RTM_GETLINK);
        cout << "Listen to link messages..." << endl;

        handlePortConfigFromConfigDB(p, cfgDb, warm);

        LinkSync sync(&appl_db, &state_db);
        NetDispatcher::getInstance().registerMessageHandler(RTM_NEWLINK, &sync);
        NetDispatcher::getInstance().registerMessageHandler(RTM_DELLINK, &sync);

        s.addSelectable(&netlink);

        while (true)
        {
            Selectable *temps;
            int ret;
            ret = s.select(&temps, DEFAULT_SELECT_TIMEOUT);

            if (ret == Select::ERROR)
            {
                cerr << "Error had been returned in select" << endl;
                continue;
            }
            else if (ret == Select::TIMEOUT)
            {
                continue;
            }
            else if (ret != Select::OBJECT)
            {
                SWSS_LOG_ERROR("Unknown return value from Select %d", ret);
                continue;
            }

            if (temps == static_cast<Selectable*>(&netlink))
            {
                /* on netlink message, check if PortInitDone should be sent out */
                if (!g_init && g_portSet.empty())
                {
                    /*
                     * After finishing reading port configuration file and
                     * creating all host interfaces, this daemon shall send
                     * out a signal to orchagent indicating port initialization
                     * procedure is done and other application could start
                     * syncing.
                     */
                    FieldValueTuple finish_notice("lanes", "0");
                    vector<FieldValueTuple> attrs = { finish_notice };
                    p.set("PortInitDone", attrs);
                    SWSS_LOG_NOTICE("PortInitDone");

                    g_init = true;
                }
            }
            else
            {
                SWSS_LOG_ERROR("Unknown object returned by select");
                continue;
            }
        }
    }
    catch (const std::exception& e)
    {
        cerr << "Exception \"" << e.what() << "\" was thrown in daemon" << endl;
        return EXIT_FAILURE;
    }
    catch (...)
    {
        cerr << "Exception was thrown in daemon" << endl;
        return EXIT_FAILURE;
    }

    return 1;
}
