#ifndef SWSS_SAISTATUSHANDLER_H
#define SWSS_SAISTATUSHANDLER_H

#include "dbconnector.h"
#include "logger.h"
#include "sai_serialize.h"

extern "C" {
#include "sai.h"
#include "saistatus.h"
}

#define ORCH_ABRT "ORCH_ABRT_STATUS"

typedef enum
{
    task_success,
    task_invalid_entry,
    task_failed,
    task_need_retry,
    task_ignore,
    task_duplicated
} task_process_status;

namespace SaiStatusHandler {
    task_process_status handleCreate(sai_api_t api, sai_status_t status, void *context);
    task_process_status handleSet(sai_api_t api, sai_status_t status, void *context);
    task_process_status handleRemove(sai_api_t api, sai_status_t status, void *context);
    task_process_status handleGet(sai_api_t api, sai_status_t status, void *context);
    bool parseFailure(task_process_status status);
    void notifyAbort();
    void clearAbortFlag();
}

#endif /* SWSS_SAISTATUSHANDLER_H */
