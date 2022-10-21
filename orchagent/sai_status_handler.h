#include "dbconnector.h"
#include "string"

extern "C" {
#include "sai.h"
#include "saistatus.h"
}

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
    const string ORCH_ABRT = "ORCH_ABRT_STATUS";
    task_process_status handleCreate(sai_api_t api, sai_status_t status, void *context = nullptr;
    task_process_status handleSet(sai_api_t api, sai_status_t status, void *context = nullptr);
    task_process_status handleRemove(sai_api_t api, sai_status_t status, void *context = nullptr);
    task_process_status handleGet(sai_api_t api, sai_status_t status, void *context = nullptr);
    bool parseFailure(task_process_status status);
    void notifyAbort();
    void clearAbortFlag();
}