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
//#include "orchdaemon.h"



/* Field Definitions */
#define TXPORTMONORCH_FIELD_CFG_PERIOD "tx_error_check_period"
#define TXPORTMONORCH_FIELD_CFG_THRESHOLD "tx_error_threshold"
#define TXPORTMONORCH_FIELD_STATE_TX_STATE "tx_status"

/* Table Names defined in Schema.h */
#define TXPORTMONORCH_CFG_TX_ERROR_TABLE "TX_ERR_CFG"
#define TXPORTMONORCH_STATE_TX_ERROR_TABLE  "TX_ERR_STATE"

/* Table to retrieve Counter Statistics */
#define TXPORTMONORCH_COUNTERTABLE  "COUNTERS"

/* aliases for application state stored in-memory of the class */
#define TXPORTMONORCH_APPL_STATUS  "tx_error_stats"
#define TXPORTMONORCH_APPL_TIMESTAMP  "tx_error_verified_latest_by"
#define TXPORTMONORCH_APPL_SAIPORTID  "tx_error_portid"
/* KEY */
#define TXPORTMONORCH_KEY_CFG_PERIOD  "GLOBAL_PERIOD"

/* Egress Error Identifier for a port */
#define TXPORTMONORCH_EGRESS_ERR_ID  "SAI_PORT_STAT_IF_OUT_ERRORS"

#define TXPORTMONORCH_SEL_TIMER     "TX_ERR_COUNTERS_POLL"

/* Helper Functions */
#define txPortState std::get<0>
#define txPortId std::get<1>
#define txPortErrCount std::get<2>
#define txPortThreshold std::get<3>


/* Data Structures which represent TxError Stats */
using TxErrorStats = std::tuple<int8_t, sai_object_id_t, uint64_t, uint64_t>;
using TxErrorStatMap = std::unordered_map<std::string, TxErrorStats> ;

// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
const std::string currentDateTime();

/* In-Memory Application data helper functions */
// Constexpr int8_t& m_portID(TxErrorStats& txStat) {return std::get<0>(txStat);}

class TxPortMonOrch : public Orch
{
	std::shared_ptr<Table> m_stateTxErrorTable;
	std::shared_ptr<Table> m_countersTable;

	uint32_t m_pollPeriod;


	const std::vector<std::string> TxStatusName = {"OK", "ERROR"};


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
	int writeToStateDb(const string& port);

public:

	TxPortMonOrch(TableConnector confDbConnector, TableConnector stateDbConnector);

	void doTask(Consumer& consumer);
	void doTask(SelectableTimer &timer);
};


