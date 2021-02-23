#include "txportmonorch.h"

swss::TxPortMonOrch::TxPortMonOrch(TableConnector confDbConnector,
		TableConnector stateDbConnector) :
		Orch(confDbConnector.first, confDbConnector.second),
		m_pollPeriod(0)
{

		m_stateTxErrorTable = make_shared<Table>(stateDbConnector.first, stateDbConnector.second);
		m_countersTable = make_shared<Table>(COUNTERS_DB, swss::COUNTERTABLE);


		/* Create an Executor with a Configurable PollTimer */
		m_pollTimer = new SelectableTimer(timespec { .tv_sec = 0, .tv_nsec = 0 });
		Orch::addExecutor(new ExecutableTimer(m_pollTimer, this, swss::TXMONORCH_POLL_EXECUTOR_NAME));


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



	return 0;
}


void swss::TxPortMonOrch::pollErrorStatistics(){

	SWSS_LOG_ENTER();

	KeyOpFieldsValuesTuple portEntry;

	for (auto entry : m_PortsTxErrStat){

		std::vector<FieldValueTuple> fields;
		int rc;

		SWSS_LOG_INFO("TX_ERROR_APPL: port %s prev tx_error_stat %ld \n", entry.first.c_str(),
		                        swss::txPortErrCount(entry.second));

		rc = this->pollOnePortErrorStatistics(entry.first, entry.second);
		if (rc != 0)
			SWSS_LOG_ERROR("TX_DRP_APPL: port %s tx_error_stat failed %d\n", entry.first.c_str(), rc);

		fields.emplace_back(swss::APPL_STATS, to_string(swss::txPortErrCount(entry.second)));
		fields.emplace_back(swss::APPL_TIMESTAMP, "0");
		fields.emplace_back(swss::APPL_SAIPORTID, to_string(swss::txPortId(entry.second)));

		SWSS_LOG_INFO("TX_DRP_APPL: port %s tx_error_stat %ld, push to db\n", entry.first.c_str(),
				swss::txPortErrCount(entry.second));
	}
}
