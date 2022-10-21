#include "orch.h"

task_process_status SaiStatusHandler::handleCreate(sai_api_t api, sai_status_t status, void *context)
{
    /*
     * This function aims to provide coarse handling of failures in sairedis create
     * operation (i.e., notify users by throwing excepions when failures happen).
     * Return value: task_success - Handled the status successfully. No need to retry this SAI operation.
     *               task_need_retry - Cannot handle the status. Need to retry the SAI operation.
     *               task_failed - Failed to handle the status but another attempt is unlikely to resolve the failure.
     * TODO: 1. Add general handling logic for specific statuses (e.g., SAI_STATUS_ITEM_ALREADY_EXISTS)
     *       2. Develop fine-grain failure handling mechanisms and replace this coarse handling
     *          in each orch.
     *       3. Take the type of sai api into consideration.
     */
    switch (api)
    {
        case SAI_API_FDB:
            switch (status)
            {
                case SAI_STATUS_SUCCESS:
                    SWSS_LOG_WARN("SAI_STATUS_SUCCESS is not expected in handleSaiCreateStatus");
                    return task_success;
                case SAI_STATUS_ITEM_ALREADY_EXISTS:
                    /*
                     *  In FDB creation, there are scenarios where the hardware learns an FDB entry before orchagent.
                     *  In such cases, the FDB SAI creation would report the status of SAI_STATUS_ITEM_ALREADY_EXISTS,
                     *  and orchagent should ignore the error and treat it as entry was explicitly created.
                     */
                    return task_success;
                default:
                    SWSS_LOG_ERROR("Encountered failure in create operation, exiting orchagent, SAI API: %s, status: %s",
                                sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
                    SaiStatusHandler::notifyAbort();
                    break;
            }
            break;
        case SAI_API_HOSTIF:
            switch (status)
            {
                case SAI_STATUS_SUCCESS:
                    return task_success;
                case SAI_STATUS_FAILURE:
                    /*
                     * Host interface maybe failed due to lane not available.
                     * In some scenarios, like SONiC virtual machine, the invalid lane may be not enabled by VM configuration,
                     * So just ignore the failure and report an error log.
                     */
                    return task_ignore;
                default:
                    SWSS_LOG_ERROR("Encountered failure in create operation, exiting orchagent, SAI API: %s, status: %s",
                                sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
                    SaiStatusHandler::notifyAbort();
                    break;
            }
            break;
        default:
            switch (status)
            {
                case SAI_STATUS_SUCCESS:
                    SWSS_LOG_WARN("SAI_STATUS_SUCCESS is not expected in handleSaiCreateStatus");
                    return task_success;
                default:
                    SWSS_LOG_ERROR("Encountered failure in create operation, exiting orchagent, SAI API: %s, status: %s",
                                sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
                    SaiStatusHandler::notifyAbort();
                    break;
            }
    }
    return task_need_retry;
}

task_process_status SaiStatusHandler::handleSet(sai_api_t api, sai_status_t status, void *context)
{
    /*
     * This function aims to provide coarse handling of failures in sairedis set
     * operation (i.e., notify users by throwing excepions when failures happen).
     * Return value: task_success - Handled the status successfully. No need to retry this SAI operation.
     *               task_need_retry - Cannot handle the status. Need to retry the SAI operation.
     *               task_failed - Failed to handle the status but another attempt is unlikely to resolve the failure.
     * TODO: 1. Add general handling logic for specific statuses
     *       2. Develop fine-grain failure handling mechanisms and replace this coarse handling
     *          in each orch.
     *       3. Take the type of sai api into consideration.
     */
    if (status == SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_WARN("SAI_STATUS_SUCCESS is not expected in handleSaiSetStatus");
        return task_success;
    }

    switch (api)
    {
        case SAI_API_PORT:
            switch (status)
            {
                case SAI_STATUS_INVALID_ATTR_VALUE_0:
                    /*
                     * If user gives an invalid attribute value, no need to retry or exit orchagent, just fail the current task
                     * and let user correct the configuration.
                     */
                    SWSS_LOG_ERROR("Encountered SAI_STATUS_INVALID_ATTR_VALUE_0 in set operation, task failed, SAI API: %s, status: %s",
                            sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
                    return task_failed;
                default:
                    SWSS_LOG_ERROR("Encountered failure in set operation, exiting orchagent, SAI API: %s, status: %s",
                            sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
                    SaiStatusHandler::notifyAbort();
                    break;
            }
            break;
        default:
            SWSS_LOG_ERROR("Encountered failure in set operation, exiting orchagent, SAI API: %s, status: %s",
                        sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
            SaiStatusHandler::notifyAbort();
            break;
    }

    return task_need_retry;
}

task_process_status SaiStatusHandler::handleRemove(sai_api_t api, sai_status_t status, void *context)
{
    /*
     * This function aims to provide coarse handling of failures in sairedis remove
     * operation (i.e., notify users by throwing excepions when failures happen).
     * Return value: task_success - Handled the status successfully. No need to retry this SAI operation.
     *               task_need_retry - Cannot handle the status. Need to retry the SAI operation.
     *               task_failed - Failed to handle the status but another attempt is unlikely to resolve the failure.
     * TODO: 1. Add general handling logic for specific statuses (e.g., SAI_STATUS_OBJECT_IN_USE,
     *          SAI_STATUS_ITEM_NOT_FOUND)
     *       2. Develop fine-grain failure handling mechanisms and replace this coarse handling
     *          in each orch.
     *       3. Take the type of sai api into consideration.
     */
    switch (status)
    {
        case SAI_STATUS_SUCCESS:
            SWSS_LOG_WARN("SAI_STATUS_SUCCESS is not expected in handleSaiRemoveStatus");
            return task_success;
        default:
            SWSS_LOG_ERROR("Encountered failure in remove operation, exiting orchagent, SAI API: %s, status: %s",
                        sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
            SaiStatusHandler::notifyAbort();
            break;
    }
    return task_need_retry;
}

task_process_status SaiStatusHandler::handleGet(sai_api_t api, sai_status_t status, void *context)
{
    /*
     * This function aims to provide coarse handling of failures in sairedis get
     * operation (i.e., notify users by throwing excepions when failures happen).
     * Return value: task_success - Handled the status successfully. No need to retry this SAI operation.
     *               task_need_retry - Cannot handle the status. Need to retry the SAI operation.
     *               task_failed - Failed to handle the status but another attempt is unlikely to resolve the failure.
     * TODO: 1. Add general handling logic for specific statuses
     *       2. Develop fine-grain failure handling mechanisms and replace this coarse handling
     *          in each orch.
     *       3. Take the type of sai api into consideration.
     */
    switch (status)
    {
        case SAI_STATUS_SUCCESS:
            SWSS_LOG_WARN("SAI_STATUS_SUCCESS is not expected in handleSaiGetStatus");
            return task_success;
        case SAI_STATUS_NOT_IMPLEMENTED:
            SWSS_LOG_ERROR("Encountered failure in get operation due to the function is not implemented, exiting orchagent, SAI API: %s",
                        sai_serialize_api(api).c_str());
            throw std::logic_error("SAI get function not implemented");
        default:
            SWSS_LOG_ERROR("Encountered failure in get operation, SAI API: %s, status: %s",
                        sai_serialize_api(api).c_str(), sai_serialize_status(status).c_str());
    }
    return task_failed;
}

bool SaiStatusHandler::parseFailure(task_process_status status)
{
    /*
     * This function parses task process status from SAI failure handling function to whether a retry is needed.
     * Return value: true - no retry is needed.
     *               false - retry is needed.
     */
    switch (status)
    {
        case task_need_retry:
            return false;
        case task_failed:
            return true;
        default:
            SWSS_LOG_WARN("task_process_status %d is not expected in parseSaiStatusFailure", status);
    }
    return true;
}

void SaiStatusHandler::notifyAbort(){
    /*
    * This function sets the ORCH_ABORT_STATUS flag in STATE_DB and aborts itself
    */
    swss::DBConnector m_db("STATE_DB", 0);
    m_db.set(ORCH_ABRT, "1");
    abort();
}

void SaiStatusHandler::clearAbortFlag(){
    /*
    * This function clears the ORCH_ABORT_STATUS flag in STATE_DB
    */
    swss::DBConnector m_db("STATE_DB", 0);
    m_db.del(ORCH_ABRT);
}