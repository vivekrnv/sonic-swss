#include "txportmonorch.h"


inline const std::string currentDateTime() {
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

		m_stateTxErrorTable = make_shared<Table>(stateDbConnector.first, stateDbConnector.second);
		m_countersTable = make_shared<Table>(COUNTERS_DB, swss::COUNTERTABLE);


		/* Create an Executor with a Configurable PollTimer */
		m_pollTimer = new SelectableTimer(timespec { .tv_sec = 0, .tv_nsec = 0 });
		Orch::addExecutor(new ExecutableTimer(m_pollTimer, this, swss::TXPORTMONORCH_POLL_EXECUTOR_NAME));


		SWSS_LOG_NOTICE("TxMonPortOrch initialized with table %s %s %s\n",
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

int swss::TxPortMonOrch::pollOnePortErrorStatistics(const string &port, TxErrorStats &stat){

	if (m_TxErrorTable.find(port) == m_TxErrorTable.end()){
		SWSS_LOG_ERROR("TX_ERR_APPL: Error table should be pre-populated before polling current statistics");
	}

	std::vector<FieldValueTuple> prevStats = m_TxErrorTable[port];

	return 0;
}


void swss::TxPortMonOrch::pollErrorStatistics(){

	SWSS_LOG_ENTER();

	KeyOpFieldsValuesTuple portEntry;

	for (auto entry : m_PortsTxErrStat){

		std::vector<FieldValueTuple> fields;
		int rc;

		SWSS_LOG_INFO("TxPortMonOrch::TX_ERR_APPL: port %s prev tx_error_stat %ld \n", entry.first.c_str(),
		                        swss::txPortErrCount(entry.second));

		rc = this->pollOnePortErrorStatistics(entry.first, entry.second);
		if (rc != 0)
			SWSS_LOG_ERROR("TxPortMonOrch::TX_ERR_APPL: port %s tx_error_stat failed %d\n", entry.first.c_str(), rc);

		fields.emplace_back(swss::APPL_STATS, to_string(swss::txPortErrCount(entry.second)));
		fields.emplace_back(swss::APPL_TIMESTAMP, currentDateTime().c_str());
		fields.emplace_back(swss::APPL_SAIPORTID, to_string(swss::txPortId(entry.second)));

		if (m_TxErrorTable.find(entry.first) != m_TxErrorTable.end()){
			m_TxErrorTable[entry.first] = fields;
		}
		else{ // This shouldn't be reached
			SWSS_LOG_INFO("TxPortMonOrch::TxPortMonOrch: old entry of port %s is not present - should not be happenig\n", entry.first.c_str());
			m_TxErrorTable.emplace(entry.first, fields);
		}

		SWSS_LOG_INFO("TxPortMonOrch::TX_ERR_APPL: port %s tx_error_stat %ld, push to in-memory db\n", entry.first.c_str(),
				swss::txPortErrCount(entry.second));
	}

	m_stateTxErrorTable->flush();
	SWSS_LOG_INFO("TxPortMonOrch::TX_ERR_STATE: flushing tables\n");
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

		if (fvField(payload) == swss::TXPORTMONORCH_FIELD_CFG_PERIOD){

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

		if (restart){
			m_pollTimer->stop();
		}

		if (shutdown){
			startTimer(m_pollPeriod);
			SWSS_LOG_INFO("TxPortMonOrch::handlePeriodUpdate TX_ERR poll timer restarted with interval %d\n", m_pollPeriod);
		}
	}
	catch (...){
		SWSS_LOG_ERROR("TxPortMonOrch::handlePeriodUpdate Failed to handle period update\n");
	}

	return 0;
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

		SWSS_LOG_INFO("TxPortMonOrch::doTask Key: %s, Operation: \n", key.c_str(), op.c_str());

		if (key == swss::TXPORTMONORCH_KEY_CFG_PERIOD){

			if (op == SET_COMMAND){
				return_status = handlePeriodUpdate(fvs);
			}
			else
			{
			    SWSS_LOG_ERROR("TxPortMonOrch::doTask Unknown Operation %s for Config Update On: in TxPortMonOrch::doTask  \n", op.c_str(), key.c_str());
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
				//reset to default
				return_status = handleThresholdUpdate(key, fvs, true);
			}
			else
			{
				SWSS_LOG_ERROR("TxPortMonOrch::doTask Unknown operation type %s when setting threshold\n", op.c_str());
			}
		}

		if (return_status){
		     SWSS_LOG_ERROR("TxPortMonOrch::doTask Handle configuration update failed index %s\n", key.c_str());
		}

		consumer.m_toSync.erase(it++);
    }
}

/* Returns 0 on success */
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

			if (swss::TXPORTMONORCH_FIELD_CFG_THRESHOLD == fvField(payload)){

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
					}
				}
				else{
					port_id = swss::txPortId(m_TxErrorTable[port]);
				}

				if (!fetchTxErrorStats(port, existingCount, port_id)){
					SWSS_LOG_ERROR("TxPortMonOrch::handleThresholdUpdate fetching error count from CounterDB failed for port %s", port.c_str());
				}

				// Fill in the states
				TxErrorStats fields;
				swss::txPortState(fields) = swss::txState::ok;
				swss::txPortId(fields) = port_id;
				swss::txPortErrCount(fields) = existingCount;
				swss::txPortThreshold(fields) = static_cast<uint64_t>(stoull(fvValue(payload)));

				m_TxErrorTable.emplace(port, fields);
				SWSS_LOG_INFO("TxPortMonOrch::handleThresholdUpdate Stats added for port %s, id : lx, Err_count %ld", port, port_id, existingCount);

				this->flushToStateDb(port);
			}
			else
			{
				SWSS_LOG_ERROR("TxPortMonOrch::handleThresholdUpdate Unknown field type %s when handle threshold for %s\n",
							   fvField(payload).c_str(), port.c_str());
				return -1;
			}
		}
	}
	catch (...){

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

			 if (field == swss::EGRESS_ERR_ID)
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

int swss::TxPortMonOrch::flushToStateDb(const string& port){

	if (m_TxErrorTable.find(port) == m_TxErrorTable.end()){
		SWSS_LOG_INFO("TxPortMonOrch: flush invoked for port %s, which doesn't have an entry in Local Map");
		return -1;
	}

	auto fields = m_TxErrorTable[port];

	vector<FieldValueTuple> fvs;

	fvs.emplace_back(swss::APPL_STATUS, swss::TxStatusName[swss::txPortState(fields)]);
	fvs.emplace_back(swss::APPL_TIMESTAMP, currentDateTime().c_str());
	fvs.emplace_back(swss::APPL_SAIPORTID, to_string(swss::txPortId(fields)));

	m_stateTxErrorTable->set(port, fvs);

	SWSS_LOG_INFO("TxPortMonOrch Flushed to State DB port %s, id : lx, state: %s", port, to_string(swss::txPortId(fields)), swss::TxStatusName[swss::txPortState(fields)]);

	return 0;
}


