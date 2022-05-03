#ifndef __LINKSYNC__
#define __LINKSYNC__

#include "dbconnector.h"
#include "producerstatetable.h"
#include "netmsg.h"
#include "exec.h"
#include "warm_restart.h"
#include "shellcmd.h"

#include <map>
#include <set>
#include <vector>
#include <set>
#include <map>
#include <list>

namespace swss {

class LinkSync : public NetMsg
{
public:
    enum { MAX_ADDR_SIZE = 64 };

    LinkSync(DBConnector *appl_db, DBConnector *state_db);

    virtual void onMsg(int nlmsg_type, struct nl_object *obj);

private:
    ProducerStateTable m_portTableProducer;
    Table m_portTable, m_statePortTable, m_stateMgmtPortTable;

    std::map<unsigned int, std::string> m_ifindexNameMap;
    std::map<unsigned int, std::string> m_ifindexOldNameMap;
};

}

void handlePortConfigFromConfigDB(swss::ProducerStateTable &, swss::DBConnector &, bool );
void handlePortConfig(swss::ProducerStateTable &, std::map<std::string, swss::KeyOpFieldsValuesTuple> &);

struct if_nameindex
{
    unsigned int if_index;
    char *if_name;
};
extern "C" { extern struct if_nameindex *if_nameindex (void) __THROW; }

#endif
