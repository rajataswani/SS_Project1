#include "anomaly.h"
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int detect_transfer_anomaly(
    int sender_account_id,
    int receiver_account_id,
    int64_t amount_cents,
    time_t now,
    AnomalyResult *result
) {
    if (!result) return -1;
    memset(result, 0, sizeof(AnomalyResult));
    result->sender_account_id = sender_account_id;
    result->receiver_account_id = receiver_account_id;
    result->amount_cents = amount_cents;
    result->window_seconds = ANOMALY_WINDOW_SECONDS;

    time_t since_time = now - ANOMALY_WINDOW_SECONDS;
    Transaction *txs = NULL;
    int count = 0;

    if (get_recent_sender_transfers(sender_account_id, since_time, &txs, &count) != 0) {
        return 0; // if error reading, assume no anomaly to avoid blocking legitimate ops unexpectedly
    }

    int match_count = 0;
    for (int i = 0; i < count; i++) {
        int64_t diff = txs[i].amount_cents - amount_cents;
        if (diff < 0) diff = -diff;
        if (diff <= ANOMALY_AMOUNT_TOLERANCE_CENTS) {
            match_count++;
        }
    }
    free(txs);

    // Current attempt is (match_count + 1)
    int total_attempts = match_count + 1;
    if (total_attempts >= ANOMALY_REPEAT_COUNT) {
        result->detected = 1;
        result->count = total_attempts;
        snprintf(result->reason, sizeof(result->reason),
                 "Repeated transfer of %lld cents (%d times in %ds)",
                 (long long)amount_cents, total_attempts, ANOMALY_WINDOW_SECONDS);
        return 1;
    }

    return 0;
}

int create_anomaly_alert(const AnomalyResult *result, int *alert_id) {
    Alert alert;
    memset(&alert, 0, sizeof(alert));
    strcpy(alert.type, "RAPID_SAME_AMOUNT_TRANSFERS");
    alert.sender_account_id = result->sender_account_id;
    alert.receiver_account_id = result->receiver_account_id;
    alert.amount_cents = result->amount_cents;
    alert.count = result->count;
    alert.window_seconds = result->window_seconds;
    snprintf(alert.reason, sizeof(alert.reason), "%s", result->reason);
    strcpy(alert.status, ALERT_OPEN_STR);
    alert.created_at = time(NULL);
    alert.resolved_by = 0;
    alert.resolved_at = 0;
    strcpy(alert.resolution_note, "Pending manager review");

    if (add_alert(&alert) != 0) {
        return -1;
    }
    if (alert_id) *alert_id = alert.alert_id;
    return 0;
}

int freeze_account(int account_id, int alert_id, const char *reason) {
    Account acc;
    if (get_account_by_id(account_id, &acc) != 0) return -1;

    User user;
    if (get_user_by_id(acc.user_id, &user) != 0) return -1;

    strcpy(user.account_status, STATUS_FROZEN_ANOMALY_STR);
    update_user(&user);

    Freeze freeze;
    memset(&freeze, 0, sizeof(freeze));
    freeze.account_id = account_id;
    freeze.alert_id = alert_id;
    strcpy(freeze.status, FREEZE_FROZEN_STR);
    strncpy(freeze.reason, reason, sizeof(freeze.reason) - 1);
    freeze.created_at = time(NULL);
    freeze.resolved_by = 0;
    freeze.resolved_at = 0;
    strcpy(freeze.resolution_note, "Account frozen due to suspicious activity");
    add_freeze(&freeze);

    return 0;
}

int freeze_transfer_parties(
    int sender_account_id,
    int receiver_account_id,
    int alert_id,
    const char *reason
) {
    freeze_account(sender_account_id, alert_id, reason);
    freeze_account(receiver_account_id, alert_id, reason);
    return 0;
}

int list_open_anomaly_alerts(char *response, size_t response_size) {
    Alert *alerts = NULL;
    int count = 0;
    if (get_all_alerts(&alerts, &count) != 0) {
        snprintf(response, response_size, "Failed to load alerts.");
        return -1;
    }

    size_t offset = 0;
    offset += snprintf(response + offset, response_size - offset,
                       "=== OPEN ANOMALY ALERTS ===\n"
                       "ID | Sender Acc | Receiver Acc | Amount (₹) | Repeat Count | Time | Reason\n"
                       "--------------------------------------------------------------------------------\n");

    int open_count = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(alerts[i].status, ALERT_OPEN_STR) == 0) {
            open_count++;
            char time_str[32];
            struct tm *tm_info = localtime(&alerts[i].created_at);
            if (tm_info) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                strcpy(time_str, "N/A");
            }

            offset += snprintf(response + offset, response_size - offset,
                               "#%d | Acc #%d | Acc #%d | ₹%.2f | %d times / %ds | %s | %s\n",
                               alerts[i].alert_id,
                               alerts[i].sender_account_id,
                               alerts[i].receiver_account_id,
                               (double)alerts[i].amount_cents / 100.0,
                               alerts[i].count,
                               alerts[i].window_seconds,
                               time_str,
                               alerts[i].reason);
            if (offset >= response_size - 100) break;
        }
    }

    if (open_count == 0) {
        offset += snprintf(response + offset, response_size - offset, "No open anomaly alerts.\n");
    }

    free(alerts);
    return 0;
}

int get_anomaly_alert_details(int alert_id, char *response, size_t response_size) {
    Alert alert;
    if (get_alert_by_id(alert_id, &alert) != 0) {
        snprintf(response, response_size, "Alert ID %d not found.", alert_id);
        return -1;
    }

    Account sender_acc, receiver_acc;
    User sender_user, receiver_user;
    char sender_info[128] = "Unknown", receiver_info[128] = "Unknown";

    if (get_account_by_id(alert.sender_account_id, &sender_acc) == 0 &&
        get_user_by_id(sender_acc.user_id, &sender_user) == 0) {
        snprintf(sender_info, sizeof(sender_info), "%s (Status: %s, UserID: %d)",
                 sender_user.username, sender_user.account_status, sender_user.user_id);
    }
    if (get_account_by_id(alert.receiver_account_id, &receiver_acc) == 0 &&
        get_user_by_id(receiver_acc.user_id, &receiver_user) == 0) {
        snprintf(receiver_info, sizeof(receiver_info), "%s (Status: %s, UserID: %d)",
                 receiver_user.username, receiver_user.account_status, receiver_user.user_id);
    }

    char created_str[32] = "N/A", resolved_str[32] = "N/A";
    struct tm *tm_info = localtime(&alert.created_at);
    if (tm_info) strftime(created_str, sizeof(created_str), "%Y-%m-%d %H:%M:%S", tm_info);
    if (alert.resolved_at > 0) {
        tm_info = localtime(&alert.resolved_at);
        if (tm_info) strftime(resolved_str, sizeof(resolved_str), "%Y-%m-%d %H:%M:%S", tm_info);
    }

    snprintf(response, response_size,
             "================ ALERT DETAILS ================\n"
             "Alert ID        : %d\n"
             "Status          : %s\n"
             "Type            : %s\n"
             "Sender Account  : #%d -> %s\n"
             "Receiver Account: #%d -> %s\n"
             "Amount          : ₹%.2f (%lld cents)\n"
             "Pattern Detected: %d transfers within %d seconds\n"
             "Reason          : %s\n"
             "Created At      : %s\n"
             "Resolved By     : User #%d\n"
             "Resolved At     : %s\n"
             "Resolution Note : %s\n"
             "===============================================\n",
             alert.alert_id,
             alert.status,
             alert.type,
             alert.sender_account_id, sender_info,
             alert.receiver_account_id, receiver_info,
             (double)alert.amount_cents / 100.0, (long long)alert.amount_cents,
             alert.count, alert.window_seconds,
             alert.reason,
             created_str,
             alert.resolved_by,
             resolved_str,
             alert.resolution_note);
    return 0;
}

int resolve_anomaly_alert(
    int manager_id,
    int alert_id,
    const char *resolution_note
) {
    Alert alert;
    if (get_alert_by_id(alert_id, &alert) != 0) {
        return -1;
    }
    if (strcmp(alert.status, ALERT_OPEN_STR) != 0 && strcmp(alert.status, ALERT_UNDER_REVIEW_STR) != 0) {
        return -2; // Already resolved or dismissed
    }

    alert.resolved_by = manager_id;
    alert.resolved_at = time(NULL);
    strcpy(alert.status, ALERT_RESOLVED_STR);
    if (resolution_note && strlen(resolution_note) > 0) {
        strncpy(alert.resolution_note, resolution_note, sizeof(alert.resolution_note) - 1);
    } else {
        strcpy(alert.resolution_note, "Resolved and unfreezed by manager");
    }
    update_alert(&alert);

    // Unfreeze sender account owner
    Account sender_acc;
    if (get_account_by_id(alert.sender_account_id, &sender_acc) == 0) {
        User u;
        if (get_user_by_id(sender_acc.user_id, &u) == 0) {
            strcpy(u.account_status, STATUS_ACTIVE_STR);
            update_user(&u);
        }
    }

    // Unfreeze receiver account owner
    Account receiver_acc;
    if (get_account_by_id(alert.receiver_account_id, &receiver_acc) == 0) {
        User u;
        if (get_user_by_id(receiver_acc.user_id, &u) == 0) {
            strcpy(u.account_status, STATUS_ACTIVE_STR);
            update_user(&u);
        }
    }

    // Update all freeze records corresponding to this alert_id
    Freeze *freezes = NULL;
    int f_count = 0;
    if (get_all_freezes(&freezes, &f_count) == 0) {
        for (int i = 0; i < f_count; i++) {
            if (freezes[i].alert_id == alert_id && strcmp(freezes[i].status, FREEZE_FROZEN_STR) == 0) {
                strcpy(freezes[i].status, FREEZE_UNFROZEN_STR);
                freezes[i].resolved_by = manager_id;
                freezes[i].resolved_at = time(NULL);
                snprintf(freezes[i].resolution_note, sizeof(freezes[i].resolution_note), "%s", alert.resolution_note);
                update_freeze(&freezes[i]);
            }
        }
        free(freezes);
    }

    return 0;
}

int list_frozen_accounts(char *response, size_t response_size) {
    User *users = NULL;
    int u_count = 0;
    if (get_all_users(&users, &u_count) != 0) {
        snprintf(response, response_size, "Failed to load users.");
        return -1;
    }

    size_t offset = 0;
    offset += snprintf(response + offset, response_size - offset,
                       "=== FROZEN ACCOUNTS ===\n"
                       "User ID | Username | Account ID | Status | Freeze Reason | Approx Freeze Time\n"
                       "--------------------------------------------------------------------------------\n");

    int frozen_found = 0;
    for (int i = 0; i < u_count; i++) {
        if (strcmp(users[i].account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
            frozen_found++;
            Account acc;
            int acc_id = -1;
            if (get_account_by_user_id(users[i].user_id, &acc) == 0) {
                acc_id = acc.account_id;
            }

            Freeze fz;
            char reason[128] = "Suspicious transaction anomaly";
            char time_str[32] = "Recently";
            if (acc_id > 0 && get_active_freeze_by_account(acc_id, &fz) == 0) {
                snprintf(reason, sizeof(reason), "%s", fz.reason);
                struct tm *tm_info = localtime(&fz.created_at);
                if (tm_info) strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            }

            offset += snprintf(response + offset, response_size - offset,
                               "#%d | %s | Acc #%d | %s | %s | %s\n",
                               users[i].user_id, users[i].username, acc_id,
                               users[i].account_status, reason, time_str);
            if (offset >= response_size - 100) break;
        }
    }

    if (frozen_found == 0) {
        offset += snprintf(response + offset, response_size - offset, "No accounts currently frozen.\n");
    }

    free(users);
    return 0;
}
