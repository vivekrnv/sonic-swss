#include <memory>
#include <unordered_map>
#include <tuple>
#include <inttypes.h>
#include <string>
#include <utility>
#include <exception>

#include <inttypes.h>

#include "orch.h"
#include "table.h"
#include "select.h"
#include "timer.h"
#include "portsorch.h"

#include "port.h"
#include "logger.h"
#include "sai_serialize.h"
#include "orchdaemon.h"

extern sai_port_api_t *sai_port_api;
extern PortsOrch*       gPortsOrch;

namespace swss{

	/* Field Definitions */
	constexpr std::string TXPORTMONORCH_FIELD_CFG_PERIOD = "tx_error_check_period";
	constexpr std::string TXPORTMONORCH_FIELD_CFG_THRESHOLD = "tx_error_threshold";
	constexpr std::string TXPORTMONORCH_FIELD_STATE_TX_STATE = "tx_status";

	/* Table Names defined in Schema.h */
	constexpr std::string CFG_TX_ERROR_TABLE = "TX_ERR_CFG";
	constexpr std::string STATE_TX_ERROR_TABLE  = "TX_ERR_STATE";

	/* Table to retrieve Counter Statistics */
	constexpr std::string COUNTERTABLE  = "COUNTERS";

	/* aliases for application state stored in-memory of the class */
	constexpr std::string APPL_STATUS  = "tx_error_stats";
	constexpr std::string APPL_TIMESTAMP =  "tx_error_verified_latest_by";
	constexpr std::string APPL_SAIPORTID =  "tx_error_portid";

	/* KEY */
	constexpr std::string TXPORTMONORCH_KEY_CFG_PERIOD  = "GLOBAL_PERIOD";

	/* Tx Port States */
	enum class txState{ // Scoped Enum
		ok, error
	};

	/* Egress Error Identifier for a port */
	constexpr std::string EGRESS_ERR_ID = "SAI_PORT_STAT_IF_OUT_ERRORS";

	constexpr std::string TXPORTMONORCH_POLL_EXECUTOR_NAME = "TX_DRP_COUNTERS_POLL";

	constexpr std::string TxStatusName[] = {"OK", "ERROR"};

	/* Data Structures which represent TxError Stats */
	using TxErrorStats = std::tuple<int8_t, sai_object_id_t, uint64_t, uint64_t>;
	using TxErrorStatMap = std::unordered_map<std::string, TxErrorStats> ;

	/* Helper Functions */
	constexpr int8_t& txPortState(TxErrorStats& txStat) {return std::get<0>(txStat);}
	constexpr sai_object_id_t& txPortId(TxErrorStats& txStat) {return std::get<1>(txStat);}
	constexpr uint64_t& txPortErrCount(TxErrorStats& txStat) {return std::get<2>(txStat);}
	constexpr uint64_t& txPortThreshold(TxErrorStats& txStat) {return std::get<3>(txStat);}


	// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
	inline const std::string currentDateTime();

	/* In-Memory Application data helper functions */
    // Constexpr int8_t& m_portID(TxErrorStats& txStat) {return std::get<0>(txStat);}

	class TxPortMonOrch : public Orch
	{
		std::shared_ptr<Table> m_stateTxErrorTable;
		std::shared_ptr<Table> m_countersTable;

		uint32_t m_pollPeriod;
      	//	uint32_t m_threshold;

		SelectableTimer* m_pollTimer;

		/* In-Memory table to keep track of Error Stats */
		TxErrorStatMap m_TxErrorTable;

		void startTimer(uint32_t interval);
		int handlePeriodUpdate(const vector<FieldValueTuple>& data);
		int handleThresholdUpdate(const string &key, const vector<FieldValueTuple>& data, bool clear);
		int pollOnePortErrorStatistics(const string &port, TxErrorStats &stat);
		void pollErrorStatistics();

		/* fetch Error Stats from Counter DB */
		/* Returns 0 on success */
		int fetchTxErrorStats(const string& port, uint64_t& currentCount, const sai_object_id_t& port_id);

		/* Returns 0 on success.... Uses the state from TxErrorStatMap */
		int flushToStateDb(const string& port);

	public:

		TxPortMonOrch(TableConnector confDbConnector, TableConnector stateDbConnector);

		void doTask(Consumer& consumer);
		void doTask(SelectableTimer &timer);
	};

}


