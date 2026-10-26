#ifndef ANOMALY_H
#define ANOMALY_H

#include "models.h"
#include <time.h>
#include <stddef.h>

int detect_transfer_anomaly(
    int sender_account_id,
    int receiver_account_id,
    int64_t amount_cents,
    time_t now,
    AnomalyResult *result
);

int create_anomaly_alert(const AnomalyResult *result, int *alert_id);

int freeze_account(int account_id, int alert_id, const char *reason);

int freeze_transfer_parties(
    int sender_account_id,
    int receiver_account_id,
    int alert_id,
    const char *reason
);

int list_open_anomaly_alerts(char *response, size_t response_size);

int get_anomaly_alert_details(int alert_id, char *response, size_t response_size);

int resolve_anomaly_alert(
    int manager_id,
    int alert_id,
    const char *resolution_note
);

int list_frozen_accounts(char *response, size_t response_size);

#endif /* ANOMALY_H */
