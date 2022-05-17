#ifndef PFC_ACTION_HANDLER_H
#define PFC_ACTION_HANDLER_H

#include <vector>
#include <memory>
#include "aclorch.h"
#include "table.h"

extern "C" {
#include "sai.h"
}

using namespace std;
using namespace swss;

struct PfcWdHwStats
{
    uint64_t txPkt;
    uint64_t txDropPkt;
    uint64_t rxPkt;
    uint64_t rxDropPkt;
};

// PFC queue interface class
// It resembles RAII behavior - pause storm is mitigated (queue is locked) on creation,
// and is restored (queue released) on removal
class PfcWdActionHandler
{
    public:
        PfcWdActionHandler(sai_object_id_t port, sai_object_id_t queue,
                uint8_t queueId, shared_ptr<Table> countersTable);
        virtual ~PfcWdActionHandler(void);

        inline sai_object_id_t getPort(void) const
        {
            return m_port;
        }

        inline sai_object_id_t getQueue(void) const
        {
            return m_queue;
        }

        inline uint8_t getQueueId(void) const
        {
            return m_queueId;
        }

        static void initWdCounters(shared_ptr<Table> countersTable, const string &queueIdStr);
        void initCounters(void);
        void commitCounters(bool periodic = false);

        virtual bool getHwCounters(PfcWdHwStats& counters)
        {
            memset(&counters, 0, sizeof(PfcWdHwStats));

            return true;
        };

    private:
        struct PfcWdQueueStats
        {
            uint64_t detectCount;
            uint64_t restoreCount;
            uint64_t txPkt;
            uint64_t txDropPkt;
            uint64_t rxPkt;
            uint64_t rxDropPkt;
            uint64_t txPktLast;
            uint64_t txDropPktLast;
            uint64_t rxPktLast;
            uint64_t rxDropPktLast;
            bool     operational;
        };

        static PfcWdQueueStats getQueueStats(shared_ptr<Table> countersTable, const string &queueIdStr);
        void updateWdCounters(const string& queueIdStr, const PfcWdQueueStats& stats);

        sai_object_id_t m_port = SAI_NULL_OBJECT_ID;
        sai_object_id_t m_queue = SAI_NULL_OBJECT_ID;
        uint8_t m_queueId = 0;
        string m_portAlias;
        shared_ptr<Table> m_countersTable = nullptr;
        PfcWdHwStats m_hwStats;
};

// Pfc queue that implements forward action by disabling PFC on queue
class PfcWdLossyHandler: public PfcWdActionHandler
{
    public:
        PfcWdLossyHandler(sai_object_id_t port, sai_object_id_t queue,
                uint8_t queueId, shared_ptr<Table> countersTable);
        virtual ~PfcWdLossyHandler(void);
        virtual bool getHwCounters(PfcWdHwStats& counters);
};

class PfcWdAclHandler: public PfcWdLossyHandler
{
    public:
        PfcWdAclHandler(sai_object_id_t port, sai_object_id_t queue,
                uint8_t queueId, shared_ptr<Table> countersTable);
        virtual ~PfcWdAclHandler(void);

        // class shared cleanup
        static void clear();
    private:
        // class shared dict: ACL table name -> ACL table
        static std::map<std::string, AclTable> m_aclTables;

        string m_strIngressTable;
        string m_strEgressTable;
        string m_strRule;
        void createPfcAclTable(sai_object_id_t port, string strTable, bool ingress);
        void createPfcAclRule(shared_ptr<AclRulePfcwd> rule, uint8_t queueId, string strTable);
};

// PFC queue that implements drop action by draining queue with buffer of zero size
class PfcWdZeroBufferHandler: public PfcWdLossyHandler
{
    public:
        PfcWdZeroBufferHandler(sai_object_id_t port, sai_object_id_t queue,
                uint8_t queueId, shared_ptr<Table> countersTable);
        virtual ~PfcWdZeroBufferHandler(void);

    private:
        /*
         * Sets lock bits on port's queue
         * to protect them from being changed by other Orch's
         */
        void setQueueLockFlag(Port& port, bool isLocked) const;

        // Singletone class for keeping shared data - zero buffer profiles
        class ZeroBufferProfile
        {
            public:
                ~ZeroBufferProfile(void);
                static sai_object_id_t getZeroBufferProfile(bool ingress);

            private:
                ZeroBufferProfile(void);
                static ZeroBufferProfile &getInstance(void);
                void createZeroBufferProfile(bool ingress);
                void destroyZeroBufferProfile(bool ingress);

                sai_object_id_t& getProfile(bool ingress)
                {
                    return ingress ? m_zeroIngressBufferProfile : m_zeroEgressBufferProfile;
                }

                sai_object_id_t& getPool(bool ingress)
                {
                    return ingress ? m_zeroIngressBufferPool : m_zeroEgressBufferPool;
                }

                sai_object_id_t m_zeroIngressBufferPool = SAI_NULL_OBJECT_ID;
                sai_object_id_t m_zeroEgressBufferPool = SAI_NULL_OBJECT_ID;
                sai_object_id_t m_zeroIngressBufferProfile = SAI_NULL_OBJECT_ID;
                sai_object_id_t m_zeroEgressBufferProfile = SAI_NULL_OBJECT_ID;
        };

        sai_object_id_t m_originalQueueBufferProfile = SAI_NULL_OBJECT_ID;
};

#endif
