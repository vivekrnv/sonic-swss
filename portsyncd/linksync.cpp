#include <string.h>
#include <errno.h>
#include <system_error>
#include <sys/socket.h>
#include <linux/if.h>
#include <netlink/route/link.h>
#include "logger.h"
#include "netmsg.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "subscriberstatetable.h"
#include "tokenize.h"
#include "exec.h"

#include "linkcache.h"
#include "portsyncd/linksync.h"
#include "warm_restart.h"
#include "shellcmd.h"

#include <iostream>
#include <set>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace swss;

#define VLAN_DRV_NAME   "bridge"
#define TEAM_DRV_NAME   "team"

const string MGMT_PREFIX = "eth";
const string INTFS_PREFIX = "Ethernet";
const string LAG_PREFIX = "PortChannel";

/*
 * This g_portSet contains all the front panel ports that the corresponding
 * host interfaces needed to be created. When this LinkSync class is
 * initialized, we check the database to see if some of the ports' host
 * interfaces are already created and remove them from this set. We will
 * remove the rest of the ports in the set when receiving the first netlink
 * message indicating that the host interfaces are created. After the set
 * is empty, we send out the signal PortInitDone. g_init is used to limit the
 * command to be run only once.
 */
set<string> g_portSet;
bool g_init;

LinkSync::LinkSync(DBConnector *appl_db, DBConnector *state_db) :
    m_portTableProducer(appl_db, APP_PORT_TABLE_NAME),
    m_portTable(appl_db, APP_PORT_TABLE_NAME),
    m_statePortTable(state_db, STATE_PORT_TABLE_NAME),
    m_stateMgmtPortTable(state_db, STATE_MGMT_PORT_TABLE_NAME)
{
    struct if_nameindex *if_ni, *idx_p;
    if_ni = if_nameindex();

    for (idx_p = if_ni;
            idx_p != NULL && idx_p->if_index != 0 && idx_p->if_name != NULL;
            idx_p++)
    {
        string key = idx_p->if_name;

        /* Explicitly store management ports oper status into the state database.
         * This piece of information is used by SNMP. */
        if (!key.compare(0, MGMT_PREFIX.length(), MGMT_PREFIX))
        {
            ostringstream cmd;
            string res;
            cmd << "cat /sys/class/net/" << shellquote(key) << "/operstate";
            try
            {
                EXEC_WITH_ERROR_THROW(cmd.str(), res);
            }
            catch (...)
            {
                SWSS_LOG_WARN("Failed to get %s oper status", key.c_str());
                continue;
            }

            /* Remove the trailing newline */
            if (res.length() >= 1 && res.at(res.length() - 1) == '\n')
            {
                res.erase(res.length() - 1);
                /* The value of operstate will be either up or down */
                if (res != "up" && res != "down")
                {
                    SWSS_LOG_WARN("Unknown %s oper status %s",
                            key.c_str(), res.c_str());
                }
                FieldValueTuple fv("oper_status", res);
                vector<FieldValueTuple> fvs;
                fvs.push_back(fv);

                m_stateMgmtPortTable.set(key, fvs);
                SWSS_LOG_INFO("Store %s oper status %s to state DB",
                        key.c_str(), res.c_str());
            }
            continue;
        }
    }

    if (!WarmStart::isWarmStart())
    {
        /* See the comments for g_portSet  */
        for (auto port_iter = g_portSet.begin(); port_iter != g_portSet.end();)
        {
            string port = *port_iter;
            vector<FieldValueTuple> temp;
            bool portFound = false;
            if (m_portTable.get(port, temp))
            {
                for (auto it : temp)
                {
                    if (fvField(it) == "admin_status")
                    {
                        port_iter = g_portSet.erase(port_iter);
                        portFound = true;
                        break;
                    }
                }
            }
            if (!portFound)
            {
                ++port_iter;
            }
        }

        for (idx_p = if_ni;
                idx_p != NULL && idx_p->if_index != 0 && idx_p->if_name != NULL;
                idx_p++)
        {
            string key = idx_p->if_name;

            /* Skip all non-frontpanel ports */
            if (key.compare(0, INTFS_PREFIX.length(), INTFS_PREFIX))
            {
                continue;
            }

            m_ifindexOldNameMap[idx_p->if_index] = key;

            ostringstream cmd;
            string res;
            /* Bring down the existing kernel interfaces */
            SWSS_LOG_INFO("Bring down old interface %s(%d)", key.c_str(), idx_p->if_index);
            cmd << "ip link set " << quoted(key) << " down";
            try
            {
                swss::exec(cmd.str(), res);
            }
            catch (...)
            {
                /* Ignore error in this flow ; */
                SWSS_LOG_WARN("Failed to bring down old interface %s(%d)", key.c_str(), idx_p->if_index);
            }
        }
    }
}

void LinkSync::onMsg(int nlmsg_type, struct nl_object *obj)
{
    SWSS_LOG_ENTER();

    if ((nlmsg_type != RTM_NEWLINK) && (nlmsg_type != RTM_DELLINK))
    {
        return;
    }

    struct rtnl_link *link = (struct rtnl_link *)obj;
    string key = rtnl_link_get_name(link);

    if (key.compare(0, INTFS_PREFIX.length(), INTFS_PREFIX) &&
        key.compare(0, LAG_PREFIX.length(), LAG_PREFIX) &&
        key.compare(0, MGMT_PREFIX.length(), MGMT_PREFIX))
    {
        return;
    }

    unsigned int flags = rtnl_link_get_flags(link);
    bool admin = flags & IFF_UP;
    bool oper = flags & IFF_RUNNING;

    char addrStr[MAX_ADDR_SIZE+1] = {0};
    nl_addr2str(rtnl_link_get_addr(link), addrStr, MAX_ADDR_SIZE);

    unsigned int ifindex = rtnl_link_get_ifindex(link);
    int master = rtnl_link_get_master(link);
    char *type = rtnl_link_get_type(link);
    unsigned int mtu = rtnl_link_get_mtu(link);

    if (type)
    {
        SWSS_LOG_NOTICE("nlmsg type:%d key:%s admin:%d oper:%d addr:%s ifindex:%d master:%d type:%s",
                       nlmsg_type, key.c_str(), admin, oper, addrStr, ifindex, master, type);
    }
    else
    {
        SWSS_LOG_NOTICE("nlmsg type:%d key:%s admin:%d oper:%d addr:%s ifindex:%d master:%d",
                       nlmsg_type, key.c_str(), admin, oper, addrStr, ifindex, master);
    }

    if (!key.compare(0, MGMT_PREFIX.length(), MGMT_PREFIX))
    {
        FieldValueTuple fv("oper_status", oper ? "up" : "down");
        vector<FieldValueTuple> fvs;
        fvs.push_back(fv);
        m_stateMgmtPortTable.set(key, fvs);
        SWSS_LOG_INFO("Store %s oper status %s to state DB",
                key.c_str(), oper ? "up" : "down");
        return;
    }

    /* teamd instances are dealt in teamsyncd */
    if (type && !strcmp(type, TEAM_DRV_NAME))
    {
        return;
    }

    /* If netlink for this port has master, we ignore that for now
     * This could be the case where the port was removed from VLAN bridge
     */
    if (master)
    {
        return;
    }

    /* In the event of swss restart, it is possible to get netlink messages during bridge
     * delete, interface delete etc which are part of cleanup. These netlink messages for
     * the front-panel interface must not be published or it will update the statedb with
     * old interface info and result in subsequent failures. Ingore all netlink messages
     * coming from old interfaces.
     */

    if (m_ifindexOldNameMap.find(ifindex) != m_ifindexOldNameMap.end())
    {
        SWSS_LOG_INFO("nlmsg type:%d Ignoring message for old interface %s(%d)",
                nlmsg_type, key.c_str(), ifindex);
        return;
    }

    /* Insert or update the ifindex to key map */
    m_ifindexNameMap[ifindex] = key;

    if (nlmsg_type == RTM_DELLINK)
    {
        m_statePortTable.del(key);
        SWSS_LOG_NOTICE("Delete %s(ok) from state db", key.c_str());
        return;
    }

    /* front panel interfaces: Check if the port is in the PORT_TABLE
     * non-front panel interfaces such as eth0, lo which are not in the
     * PORT_TABLE are ignored. */
    vector<FieldValueTuple> temp;
    if (m_portTable.get(key, temp))
    {
        g_portSet.erase(key);
        FieldValueTuple tuple("state", "ok");
        FieldValueTuple admin_status("admin_status", (admin ? "up" : "down"));
        FieldValueTuple port_mtu("mtu", to_string(mtu));
        vector<FieldValueTuple> vector;
        vector.push_back(tuple);
        FieldValueTuple op("netdev_oper_status", oper ? "up" : "down");
        vector.push_back(op);
        vector.push_back(admin_status);
        vector.push_back(port_mtu);
        m_statePortTable.set(key, vector);
        SWSS_LOG_NOTICE("Publish %s(ok:%s) to state db", key.c_str(), oper ? "up" : "down");
    }
    else
    {
        SWSS_LOG_NOTICE("Cannot find %s in port table", key.c_str());
    }
}

static void notifyPortConfigDone(ProducerStateTable &p)
{
    /* Notify that all ports added */
    FieldValueTuple finish_notice("count", to_string(g_portSet.size()));
    vector<FieldValueTuple> attrs = { finish_notice };
    p.set("PortConfigDone", attrs);
}

void handlePortConfigFromConfigDB(ProducerStateTable &p, DBConnector &cfgDb, bool warm)
{
    SWSS_LOG_ENTER();

    SWSS_LOG_NOTICE("Getting port configuration from ConfigDB...");

    Table table(&cfgDb, CFG_PORT_TABLE_NAME);
    std::vector<FieldValueTuple> ovalues;
    std::vector<string> keys;
    table.getKeys(keys);

    if (keys.empty())
    {
        SWSS_LOG_NOTICE("ConfigDB does not have port information, "
                        "however ports can be added later on, continuing...");
    }

    for ( auto &k : keys )
    {
        table.get(k, ovalues);
        vector<FieldValueTuple> attrs;
        for ( auto &v : ovalues )
        {
            FieldValueTuple attr(v.first, v.second);
            attrs.push_back(attr);
        }
        if (!warm)
        {
            p.set(k, attrs);
        }
        g_portSet.insert(k);
    }
    if (!warm)
    {
        notifyPortConfigDone(p);
    }

}

void handlePortConfig(ProducerStateTable &p, map<string, KeyOpFieldsValuesTuple> &port_cfg_map)
{
    auto it = port_cfg_map.begin();
    while (it != port_cfg_map.end())
    {
        KeyOpFieldsValuesTuple entry = it->second;
        string key = kfvKey(entry);
        string op  = kfvOp(entry);
        auto values = kfvFieldsValues(entry);

        /* only push down port config when port is not in hostif create pending state */
        if (g_portSet.find(key) == g_portSet.end())
        {
            /* No support for port delete yet */
            if (op == SET_COMMAND)
            {
                p.set(key, values);
            }

            it = port_cfg_map.erase(it);
        }
        else
        {
            it++;
        }
    }
}