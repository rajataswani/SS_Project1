#ifndef MODELS_H
#define MODELS_H

#include <time.h>
#include <stdint.h>

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_HASH_LEN 65
#define MAX_ROLE_LEN 16
#define MAX_STATUS_LEN 32
#define MAX_DETAILS_LEN 128
#define MAX_MSG_LEN 256
#define MAX_NOTE_LEN 256

#define DEFAULT_PORT 8080
#define BUFFER_SIZE 4096

/* Role strings */
#define ROLE_CUSTOMER_STR "CUSTOMER"
#define ROLE_EMPLOYEE_STR "EMPLOYEE"
#define ROLE_MANAGER_STR  "MANAGER"
#define ROLE_ADMIN_STR    "ADMIN"

/* User account status strings */
#define STATUS_ACTIVE_STR         "ACTIVE"
#define STATUS_FROZEN_ANOMALY_STR "FROZEN_ANOMALY"
#define STATUS_DEACTIVATED_STR    "DEACTIVATED"

/* Transaction types */
#define TX_DEPOSIT_STR      "DEPOSIT"
#define TX_WITHDRAW_STR     "WITHDRAW"
#define TX_TRANSFER_OUT_STR "TRANSFER_OUT"
#define TX_TRANSFER_IN_STR  "TRANSFER_IN"
#define TX_LOAN_CREDIT_STR  "LOAN_CREDIT"

/* Loan statuses */
#define LOAN_PENDING_STR    "PENDING"
#define LOAN_ASSIGNED_STR   "ASSIGNED"
#define LOAN_PROCESSING_STR "PROCESSING"
#define LOAN_APPROVED_STR   "APPROVED"
#define LOAN_REJECTED_STR   "REJECTED"

/* Alert statuses */
#define ALERT_OPEN_STR         "OPEN"
#define ALERT_UNDER_REVIEW_STR "UNDER_REVIEW"
#define ALERT_RESOLVED_STR     "RESOLVED"
#define ALERT_DISMISSED_STR    "DISMISSED"

/* Freeze statuses */
#define FREEZE_FROZEN_STR   "FROZEN"
#define FREEZE_UNFROZEN_STR "UNFROZEN"

/* Anomaly detection settings */
#define ANOMALY_WINDOW_SECONDS         60
#define ANOMALY_REPEAT_COUNT           3
#define ANOMALY_AMOUNT_TOLERANCE_CENTS 0

typedef struct {
    int user_id;
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_HASH_LEN];
    char role[MAX_ROLE_LEN];
    int active;
    char account_status[MAX_STATUS_LEN];
} User;

typedef struct {
    int account_id;
    int user_id;
    int64_t balance_cents;
    int active;
} Account;

typedef struct {
    int transaction_id;
    int account_id;
    char type[20];
    int64_t amount_cents;
    int related_account_id;
    char details[MAX_DETAILS_LEN];
    time_t timestamp;
} Transaction;

typedef struct {
    int loan_id;
    int account_id;
    int64_t amount_cents;
    char status[20];
    int assigned_employee_id;
    time_t created_at;
    time_t processed_at;
} Loan;

typedef struct {
    int feedback_id;
    int user_id;
    char message[MAX_MSG_LEN];
    time_t timestamp;
} Feedback;

typedef struct {
    int alert_id;
    char type[32];
    int sender_account_id;
    int receiver_account_id;
    int64_t amount_cents;
    int count;
    int window_seconds;
    char reason[MAX_DETAILS_LEN];
    char status[20];
    time_t created_at;
    int resolved_by;
    time_t resolved_at;
    char resolution_note[MAX_NOTE_LEN];
} Alert;

typedef struct {
    int freeze_id;
    int account_id;
    int alert_id;
    char status[20];
    char reason[MAX_DETAILS_LEN];
    time_t created_at;
    int resolved_by;
    time_t resolved_at;
    char resolution_note[MAX_NOTE_LEN];
} Freeze;

typedef struct {
    int detected;
    int count;
    int sender_account_id;
    int receiver_account_id;
    int64_t amount_cents;
    int window_seconds;
    char reason[MAX_DETAILS_LEN];
} AnomalyResult;

#endif /* MODELS_H */
