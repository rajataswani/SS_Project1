#ifndef STORAGE_H
#define STORAGE_H

#include "models.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_DIR "data"
#define BANK_LOCK_FILE "data/bank.lock"
#define USERS_FILE "data/users.txt"
#define ACCOUNTS_FILE "data/accounts.txt"
#define TRANSACTIONS_FILE "data/transactions.txt"
#define LOANS_FILE "data/loans.txt"
#define FEEDBACK_FILE "data/feedback.txt"
#define ALERTS_FILE "data/alerts.txt"
#define FREEZES_FILE "data/freezes.txt"

/* Storage and locking initialization */
int storage_init(void);

/* Global database locking (shared / exclusive) */
int lock_bank_shared(void);
int lock_bank_exclusive(void);
int unlock_bank(void);

/* Single session lock per user */
int acquire_session_lock(int user_id);
void release_session_lock(int fd, int user_id);

/* Sanitizer for text fields */
void sanitize_text(char *str);

/* User storage */
int get_user_by_id(int user_id, User *user);
int get_user_by_username(const char *username, User *user);
int add_user(User *user);
int update_user(const User *user);
int get_all_users(User **users, int *count);

/* Account storage */
int get_account_by_id(int account_id, Account *account);
int get_account_by_user_id(int user_id, Account *account);
int add_account(Account *account);
int update_account(const Account *account);
int get_all_accounts(Account **accounts, int *count);

/* Transaction storage */
int add_transaction(Transaction *tx);
int get_transactions_by_account(int account_id, Transaction **txs, int *count);
int get_recent_sender_transfers(int sender_account_id, time_t since_time, Transaction **txs, int *count);

/* Loan storage */
int add_loan(Loan *loan);
int get_loan_by_id(int loan_id, Loan *loan);
int update_loan(const Loan *loan);
int get_all_loans(Loan **loans, int *count);

/* Feedback storage */
int add_feedback(Feedback *fb);
int get_all_feedback(Feedback **fbs, int *count);

/* Alert storage */
int add_alert(Alert *alert);
int get_alert_by_id(int alert_id, Alert *alert);
int update_alert(const Alert *alert);
int get_all_alerts(Alert **alerts, int *count);

/* Freeze storage */
int add_freeze(Freeze *freeze);
int get_all_freezes(Freeze **freezes, int *count);
int update_freeze(const Freeze *freeze);
int get_active_freeze_by_account(int account_id, Freeze *freeze);

/* Seed default data if files are missing */
void seed_initial_data_if_needed(void);

#endif /* STORAGE_H */
