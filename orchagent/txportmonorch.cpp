#include "txportmonorch.h"

const std::vector<std::string> TxStatusName = {"OK", "ERROR"};

const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
    return buf;
}

swss::TxPortMonOrch::TxPortMonOrch(TableConnector confDbConnector,
		TableConnector stateDbConnector) :
		Orch(confDbConnector.first, confDbConnector.second),
		m_pollPeriod(0)
{

		DBConnector counters_db("APPL_DB", 0);

		m_stateTxErrorTable = make_shared<Table>(stateDbConnector.first, stateDbConnector.second);
		m_countersTable = make_shared<Table>(&counters_db, TXPORTMONORCH_COUNTERTABLE);


		/* Create an Executor with a Configurable PollTimer */
		m_pollTimer = new SelectableTimer(timespec { .tv_sec = 0, .tv_nsec = 0 });
		Orch::addExecutor(new ExecutableTimer(m_pollTimer, this, TXPORTMONORCH_SEL_TIMER));


		SWSS_LOG_NOTICE("TxMonPortOrch initialized with table %s %s\n",
		                    stateDbConnector.second.c_str(),
		                    confDbConnector.second.c_str());
}

void swss::TxPortMonOrch::startTimer(uint32_t interval)
{
    SWSS_LOG_ENTER();

    try
    {
        auto interv = timespec { .tv_sec = interval, .tv_nsec = 0 };

        SWSS_LOG_INFO("TxMonPortOrch: startTimer,  find executor %p\n", m_pollTimer);
        m_pollTimer->setInterval(interv);
        m_pollTimer->stop();
        m_pollTimer->start();
        m_pollPeriod = interval;
    }
    catch (...)
    {
        SWSS_LOG_ERROR("TxMonPortOrch: Failed to start timer\n");
    }
}

void swss::TxPortMonOrch::doTask(SelectableTimer &timer){
	 SWSS_LOG_INFO("TxMonOrch: doTask invoked with timer update\n");
	 this->pollErrorStatistics();
}

/* Pools error stats from counter db for a port and updates the state accordingly */
int swss::TxPortMonOrch::pollOnePortErrorStatistics(const string &port, TxErrorStats &stat){

	if (m_TxErrorTable.find(port) == m_TxErrorTable.end()){
		SWSS_LOG_ERROR("TxPortMonOrch::pollOnePortErrorStatistics: Local map should have been be pre-populated before polling current statistics");
		return 0;
	}

	uint64_t prevCount = swss::txPortErrCount(stat);
	uint64_t currCount;

	if (!this->fetchTxErrorStats(port, currCount, swss::txPortId(stat))){
		SWSS_LOG_ERROR("TxPortMonOrch::pollOnePortErrorStatistics fetching error count from CounterDB failed for port %s", port.c_str());
		return -1;
	}

	// TODO: Keep Track of last updated time and also use that info for judging if the port actually went to an error state
	if (currCount - prevCount >= swss::txPortThreshold(stat)){
		swss::txPortState(stat) = swss::txState::error;
	}

	swss::txPortErrCount(stat) = currCount;

	this->writeToStateDb(port);

	return 0;
}


void swss::TxPortMonOrch::pollErrorStatistics(){

	SWSS_LOG_ENTER();

	KeyOpFieldsValuesTuple portEntry;

	for (auto entry : m_TxErrorTable){

		std::vector<FieldValueTuple> fields;
		int rc;

		SWSS_LOG_INFO("TxPortMonOrch::pollErrorStatistics:Port %s BEFORE-POLL tx_error_stat %ld \n", entry.first.c_str(),
		                        swss::txPortErrCount(entry.second));

		rc = this->pollOnePortErrorStatistics(entry.first, entry.second);
		if (rc != 0)
			SWSS_LOG_ERROR("TxPortMonOrch::pollErrorStatistics: port %s tx_error_stat failed %d\n", entry.first.c_str(), rc);

		SWSS_LOG_INFO("TxPortMonOrch::pollErrorStatistics:Port %s AFTER-POLL tx_error_stat %ld \n", entry.first.c_str(),
				                        swss::txPortErrCount(entry.second));

	}

	SWSS_LOG_INFO("TxPortMonOrch::pollErrorStatistics Polling completed for all ports");
}


/* Handle Configuration Update */
/* Can include either polling-period, threshold or both*/
void swss::TxPortMonOrch::doTask(Consumer& consumer){

	SWSS_LOG_ENTER();
	SWSS_LOG_INFO("TxPortMonOrch::doTask Config Update\n");

	int return_status = 0;

	if (!gPortsOrch->allPortsReady())
	{
		SWSS_LOG_INFO("TxPortMonOrch::doTask Ports not ready yet \n");
		return;
	}

	auto it = consumer.m_toSync.begin();
	while (it != consumer.m_toSync.end())
	{
		KeyOpFieldsValuesTuple t = it->second;

		string key = kfvKey(t);
	    string op = kfvOp(t);
		vector<FieldValueTuple> fvs = kfvFieldsValues(t);

		SWSS_LOG_INFO("TxPortMonOrch::doTask Key: %s, Operation: \n", key.c_str());

		if (key == TXPORTMONORCH__KEY_CFG_PERIOD){

			if (op == SET_COMMAND){
				return_status = handlePeriodUpdate(fvs);
			}
			else
			{
			    SWSS_LOG_ERROR("TxPortMonOrch::doTask Unknown Operation %s for Pooling Period Config Update for key %s\n", op.c_str(), key.c_str());
			}
		}
		// TODO : Check if the key is a valid alias of interface
		else {
			 if (op == SET_COMMAND)
			 {
				//fetch the value which reprsents threshold
				return_status = handleThresholdUpdate(key, fvs, false);
			 }
			else if (op == DEL_COMMAND)
			{
				//remove entry from state table and local map
				return_status = handleThresholdUpdate(key, fvs, true);
			}
			else
			{
				SWSS_LOG_ERROR("TxPortMonOrch::doTask Unknown operation type %s when setting threshold\n", op.c_str());
			}
		}

		if (return_status < 0){
		     SWSS_LOG_ERROR("TxPortMonOrch::FAIL Not in the Correct State, error reported on port: %s\n", key.c_str());
		}

		consumer.m_toSync.erase(it++);
    }
}


/* Returns 0 on success */
int swss::TxPortMonOrch::handlePeriodUpdate(const vector<FieldValueTuple>& data){


	bool restart = false;
	bool shutdown = false;

	SWSS_LOG_ENTER();


	//	if (data.size() > 1){
	//		SWSS_LOG_INFO("TxPortMonOrch::handlePeriodUpdate Update Size > 1: Check With Redis-subscription mechanism inside SWSS");
	//	}

	//Only the latest update is bothered about
	try {
		FieldValueTuple payload = *data.rbegin();

		if (fvField(payload) == TXPORTMONORCH_FIELD_CFG_PERIOD){

			uint32_t periodToSet = static_cast<uint32_t>(fvValue(payload));

			if (periodToSet == 0){
				shutdown = true;
			}
			else if(periodToSet != m_pollPeriod){
				restart = true;
				m_pollPeriod = periodToSet;
			}
			else{
				// do nothing
			}
		}
		else{
			SWSS_LOG_ERROR("TxPortMonOrch::handlePeriodUpdate Unknown field type %s\n", fvField(payload).c_str());
			return -1;
		}

		/* Shutdown clears complete state and application state */
		if (shutdown){
			m_pollTimer->stop(); // Stop the timer
			for (auto port : m_TxErrorTable){
				m_stateTxErrorTable->del(port.first); // Clear everything from the sSTATE_TX_ERROR_TABLE
				SWSS_LOG_INFO("TxPortMonOrch::handlePeriodUpdate Everything cleared in state tx table for the port %s\n", port.first.c_str());
			}
			m_TxErrorTable.clear(); //Clean everything from Local Map
			SWSS_LOG_INFO("TxPortMonOrch::handlePeriodUpdate Complete Application data has been cleared ");

		}

		if (restart){
			this->startTimer(m_pollPeriod);
			SWSS_LOG_INFO("TxPortMonOrch::handlePeriodUpdate TX_ERR poll timer restarted with interval %d\n", m_pollPeriod);
		}
	}
	catch (...){
		SWSS_LOG_ERROR("TxPortMonOrch::handlePeriodUpdate Failed\n");
		return -1;
	}

	return 0;
}


/*
 * Returns 0 on success
 	      -1 in something failed
 	       1 Invalid Parameters recieved in the config
*/
int swss::TxPortMonOrch::handleThresholdUpdate(const string &port, const vector<FieldValueTuple>& data, bool clear){

	try {
		if (clear){
			m_TxErrorTable.erase(port); //Create from Local Map
			m_stateTxErrorTable->del(port); // Clear from State Table
			SWSS_LOG_INFO("TxPortMonOrch::handleThresholdUpdate threshold cleared for port %s\n", port.c_str());
		}
		else{
			// Only the latest update is considered.
			auto payload = *data.rbegin();

			if (fvField(payload) == TXPORTMONORCH_FIELD_CFG_THRESHOLD){

				sai_object_id_t port_id;
				uint64_t existingCount;

				// Port is added for the first time
				if (m_TxErrorTable.find(port) == m_TxErrorTable.end()){
					Port saiport;
					if (gPortsOrch->getPort(port, saiport))
					{
						port_id = saiport.m_port_id;
					}
					else{
						SWSS_LOG_ERROR("TxPortMonOrch::handleThresholdUpdate getPort id failed for port %s", port.c_str());
						throw 20;
					}
				}
				else{
					// if threshold already same, don't do anything
					if (swss::txPortThreshold(m_TxErrorTable[port]) == static_cast<uint64_t>(stoull(fvValue(payload)))) {
						SWSS_LOG_INFO("TxPortMonOrch::handleThresholdUpdate Parameter has not changed for threshold on port %s, in recent config update", port.c_str());
						return 0;
					}

					port_id = swss::txPortId(m_TxErrorTable[port]);
				}

				if (!fetchTxErrorStats(port, existingCount, port_id)){
					SWSS_LOG_ERROR("TxPortMonOrch::handleThresholdUpdate fetching error count from CounterDB failed for port %s", port.c_str());
					throw 20;
				}

				// Fill in the states
				TxErrorStats fields;
				swss::txPortState(fields) = static_cast<int8_t>(swss::txState::ok);
				swss::txPortId(fields) = port_id;
				swss::txPortErrCount(fields) = existingCount;
				swss::txPortThreshold(fields) = static_cast<uint64_t>(stoull(fvValue(payload)));

				m_TxErrorTable.emplace(port, fields);
				SWSS_LOG_INFO("TxPortMonOrch::handleThresholdUpdate Details added/Updated for port %s, id : lx, Err_count %ld, Threshold_set %ld", port.c_str(), swss::txPortId(fields), swss::txPortErrCount(fields), swss::txPortThreshold(fields));

				this->writeToStateDb(port);
			}
			else
			{
				SWSS_LOG_ERROR("TxPortMonOrch::handleThresholdUpdate Unknown field type %s when handle threshold for %s\n",
							   fvField(payload).c_str(), port.c_str());
				return 1;
			}
		}
	}
	catch (...){
		SWSS_LOG_ERROR("TxPortMonOrch::handleThresholdUpdate failed for port %s\n", port.c_str());
		return -1;
	}

	return 0;
}

int swss::TxPortMonOrch::fetchTxErrorStats(const string& port, uint64_t& currentCount, const sai_object_id_t& port_id){

	vector<FieldValueTuple> fieldValues;

	 if (m_countersTable->get(sai_serialize_object_id(port_id), fieldValues)){

		 for (const auto& fv : fieldValues)
		 {
			 const auto field = fvField(fv);
			 const auto value = fvValue(fv);

			 if (field == TXPORTMONORCH_EGRESS_ERR_ID)
			 {
				 currentCount = static_cast<uint64_t>(stoul(value));
				 SWSS_LOG_INFO("TxPortMonOrch::fetchTxErrorStats TX_ERR_POLL: %s found %ld %s\n", field.c_str(), currentCount, value.c_str());
				 break;
			 }
		 }

	 }
	 else{
	     SWSS_LOG_INFO("TxPortMonOrch::fetchTxErrorStats failed to fetch statistics for port %s id: %lx \n", port.c_str(), port_id);
	     return -1;
	 }

	 return 0;
}

int swss::TxPortMonOrch::writeToStateDb(const string& port){

	if (m_TxErrorTable.find(port) == m_TxErrorTable.end()){
		SWSS_LOG_INFO("TxPortMonOrch: flush invoked for port %s, which doesn't have an entry in Local Map");
		return -1;
	}

	auto& fields = m_TxErrorTable[port];

	vector<FieldValueTuple> fvs;

	fvs.emplace_back(TXPORTMONORCH_APPL_STATUS, TxStatusName[swss::txPortState(fields)]);
	fvs.emplace_back(TXPORTMONORCH_APPL_TIMESTAMP, currentDateTime().c_str());
	fvs.emplace_back(TXPORTMONORCH_APPL_SAIPORTID, to_string(swss::txPortId(fields)));

	m_stateTxErrorTable->set(port, fvs);

	m_stateTxErrorTable->flush();

	SWSS_LOG_INFO("TxPortMonOrch Flushed to State DB port %s, id : lx, state: %s", port, to_string(swss::txPortId(fields)), TxStatusName[swss::txPortState(fields)]);

	return 0;
}


