#include <memory>
#include <unordered_map>
#include <tuple>
#include <inttypes.h>
#include <string>
#include "orch.h"
#include "table.h"
#include "select.h"
#include "timer.h"
#include "portsorch.h"

#include "port.h"
#include "logger.h"
#include "sai_serialize.h"



namespace swss{

	/* Field Definitions */
	constexpr std::string TXMONORCH_FIELD_CFG_PERIOD = "tx_error_check_period";
	constexpr std::string TXMONORCH_FIELD_CFG_THRESHOLD = "tx_error_threshold";
	constexpr std::string TXMONORCH_FIELD_STATE_TX_STATE = "tx_status";

	/* Table Names defined in Schema.h */
	constexpr std::string CFG_TX_ERROR_TABLE = "TX_ERR_CFG";
	constexpr std::string STATE_TX_ERROR_TABLE  = "TX_ERR_STATE";

	/* Table to retrieve Counter Statistics */
	constexpr std::string COUNTERTABLE  = "COUNTERS";

	/* aliases for application state stored in-memory of the class */
	constexpr std::string APPL_STATS  = "tx_error_stats";
	constexpr std::string APPL_TIMESTAMP =  "tx_error_timestamp";
	constexpr std::string APPL_SAIPORTID =  "tx_error_portid";

	/* Tx Port States */
	enum class txState{ // Scoped Enum
		ok, error
	};

	constexpr std::string TXMONORCH_POLL_EXECUTOR_NAME = "TX_DRP_COUNTERS_POLL";

	constexpr std::string TxStatusName[] = {"OK", "ERROR"};

	/* Data Structures which represent TxError Stats */
	using TxErrorStats = std::tuple<int8_t, sai_object_id_t, uint64_t, uint64_t>;
	using TxErrorStatMap = std::unordered_map<std::string, TxErrorStats> ;

	/* Helper Functions */
	constexpr int8_t& txPortState(TxErrorStats& txStat) {return std::get<0>(txStat);}
	constexpr sai_object_id_t& txPortId(TxErrorStats& txStat) {return std::get<1>(txStat);}
	constexpr uint64_t& txPortErrCount(TxErrorStats& txStat) {return std::get<2>(txStat);}
	constexpr uint64_t& txPortThreshold(TxErrorStats& txStat) {return std::get<3>(txStat);}


	class TxPortMonOrch : public Orch
	{
		std::shared_ptr<Table> m_stateTxErrorTable;
		std::shared_ptr<Table> m_countersTable;

		uint32_t m_pollPeriod;

		SelectableTimer* m_pollTimer;

		TxErrorStatMap m_PortsTxErrStat;

		void startTimer(uint32_t interval);
		int handlePeriodUpdate(const vector<FieldValueTuple>& data);
		int handleThresholdUpdate(const string &key, const vector<FieldValueTuple>& data, bool clear);
		int pollOnePortErrorStatistics(const string &port, TxErrorStats &stat);
		void pollErrorStatistics();

	public:

		TxPortMonOrch(TableConnector confDbConnector, TableConnector stateDbConnector);

		void doTask(Consumer& consumer);
		void doTask(SelectableTimer &timer);
	};

}


