#define _GNU_SOURCE
#include "models.h"
#include "protocol.h"
#include "storage.h"
#include "anomaly.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void send_response(int fd, const char *resp) {
    if (write(fd, resp, strlen(resp)) < 0) {}
    if (write(fd, "\n", 1) < 0) {}
}

static int parse_command(char *line, char **args, int max_args) {
    int count = 0;
    char *p = line;
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[len - 1] = '\0';
        len--;
    }

    args[count++] = p;
    while (*p && count < max_args) {
        if (*p == '|') {
            *p = '\0';
            args[count++] = p + 1;
        }
        p++;
    }
    return count;
}

static void handle_client(int client_fd) {
    int user_id = 0;
    char role[MAX_ROLE_LEN] = "";
    char username[MAX_USERNAME_LEN] = "";
    int session_lock_fd = -1;

    char buffer[BUFFER_SIZE];
    char leftover[BUFFER_SIZE] = "";
    ssize_t bytes_read;

    while ((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';

        char full_input[BUFFER_SIZE * 2];
        snprintf(full_input, sizeof(full_input), "%s%s", leftover, buffer);
        leftover[0] = '\0';

        char *line_start = full_input;
        char *newline_pos;

        while ((newline_pos = strchr(line_start, '\n')) != NULL) {
            *newline_pos = '\0';
            char *line = line_start;
            line_start = newline_pos + 1;

            if (strlen(line) == 0) continue;

            char *args[16];
            int argc = parse_command(line, args, 16);
            if (argc == 0) continue;

            const char *cmd = args[0];

            /* --- LOGIN --- */
            if (strcmp(cmd, "LOGIN") == 0) {
                if (argc < 4) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: LOGIN|role|username|password");
                    continue;
                }
                if (user_id > 0) {
                    send_response(client_fd, "ERROR|ALREADY_AUTHENTICATED|This session is already authenticated. Please log out first.");
                    continue;
                }
                const char *req_role = args[1];
                const char *req_user = args[2];
                const char *req_pass = args[3];

                lock_bank_shared();
                User u;
                if (get_user_by_username(req_user, &u) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|AUTH_FAILED|Invalid username or password.");
                    continue;
                }

                char hash[65];
                sha256_hash_string(req_pass, hash);
                if (strcmp(u.password_hash, hash) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|AUTH_FAILED|Invalid username or password.");
                    continue;
                }

                if (strcasecmp(u.role, req_role) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|ROLE_MISMATCH|User role does not match requested role.");
                    continue;
                }

                if (u.active == 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|ACCOUNT_DEACTIVATED|Account is deactivated. Contact bank.");
                    continue;
                }
                unlock_bank();

                // Single session lock
                int s_fd = acquire_session_lock(u.user_id);
                if (s_fd < 0) {
                    send_response(client_fd, ERR_ALREADY_LOGGED_IN);
                    continue;
                }

                user_id = u.user_id;
                session_lock_fd = s_fd;
                snprintf(role, sizeof(role), "%s", u.role);
                snprintf(username, sizeof(username), "%s", u.username);

                if (strcmp(u.account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
                    char resp[256];
                    snprintf(resp, sizeof(resp), "SUCCESS|LOGIN_SUCCESS|FROZEN|%d|%s|Welcome, %s! WARNING: Your account is currently FROZEN due to transaction anomalies.",
                             user_id, role, username);
                    send_response(client_fd, resp);
                } else {
                    char resp[256];
                    snprintf(resp, sizeof(resp), "SUCCESS|LOGIN_SUCCESS|ACTIVE|%d|%s|Welcome, %s!",
                             user_id, role, username);
                    send_response(client_fd, resp);
                }
            }
            /* --- REGISTER --- */
            else if (strcmp(cmd, "REGISTER") == 0) {
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: REGISTER|username|password");
                    continue;
                }
                const char *new_user = args[1];
                const char *new_pass = args[2];
                if (strlen(new_user) == 0 || strlen(new_pass) == 0) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Username and password cannot be empty.");
                    continue;
                }

                lock_bank_exclusive();
                User u;
                memset(&u, 0, sizeof(u));
                strncpy(u.username, new_user, sizeof(u.username) - 1);
                sanitize_text(u.username);
                sha256_hash_string(new_pass, u.password_hash);
                strcpy(u.role, ROLE_CUSTOMER_STR);
                u.active = 1;
                strcpy(u.account_status, STATUS_ACTIVE_STR);

                int res = add_user(&u);
                if (res == -2) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|USERNAME_TAKEN|Username already exists. Please choose another.");
                    continue;
                } else if (res != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|STORAGE_ERROR|Failed to register user.");
                    continue;
                }

                Account acc;
                memset(&acc, 0, sizeof(acc));
                acc.user_id = u.user_id;
                acc.balance_cents = 0;
                acc.active = 1;
                add_account(&acc);

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Registration successful! Your Account ID is #%d. Please log in.", acc.account_id);
                send_response(client_fd, resp);
            }
            /* --- LOGOUT --- */
            else if (strcmp(cmd, "LOGOUT") == 0) {
                if (user_id > 0) {
                    release_session_lock(session_lock_fd, user_id);
                    session_lock_fd = -1;
                    user_id = 0;
                    role[0] = '\0';
                    username[0] = '\0';
                    send_response(client_fd, "SUCCESS|Logged out successfully.");
                } else {
                    send_response(client_fd, "ERROR|NOT_LOGGED_IN|You are not logged in.");
                }
            }
            /* --- GET_MY_ACCOUNT_ID --- */
            else if (strcmp(cmd, "GET_MY_ACCOUNT_ID") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                lock_bank_shared();
                Account acc;
                if (get_account_by_user_id(user_id, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|No account found for user.");
                    continue;
                }
                User u;
                get_user_by_id(user_id, &u);
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|%d|%s", acc.account_id, u.account_status);
                send_response(client_fd, resp);
            }
            /* --- VIEW_BALANCE --- */
            else if (strcmp(cmd, "VIEW_BALANCE") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                lock_bank_shared();
                Account acc;
                if (get_account_by_user_id(user_id, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Account record not found.");
                    continue;
                }
                User u;
                get_user_by_id(user_id, &u);
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Account #%d | Balance: ₹%.2f | Status: %s",
                         acc.account_id, (double)acc.balance_cents / 100.0, u.account_status);
                send_response(client_fd, resp);
            }
            /* --- DEPOSIT --- */
            else if (strcmp(cmd, "DEPOSIT") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: DEPOSIT|amount_cents");
                    continue;
                }
                int64_t amount_cents = atoll(args[1]);
                if (amount_cents <= 0) {
                    send_response(client_fd, "ERROR|INVALID_AMOUNT|Deposit amount must be positive.");
                    continue;
                }

                lock_bank_exclusive();
                User u;
                get_user_by_id(user_id, &u);
                if (strcmp(u.account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_FROZEN);
                    continue;
                }
                if (u.active == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_DEACTIVATED);
                    continue;
                }

                Account acc;
                if (get_account_by_user_id(user_id, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Account not found.");
                    continue;
                }

                acc.balance_cents += amount_cents;
                update_account(&acc);

                Transaction tx;
                memset(&tx, 0, sizeof(tx));
                tx.account_id = acc.account_id;
                strcpy(tx.type, TX_DEPOSIT_STR);
                tx.amount_cents = amount_cents;
                tx.related_account_id = 0;
                strcpy(tx.details, "Cash deposit");
                tx.timestamp = time(NULL);
                add_transaction(&tx);

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Deposited ₹%.2f successfully. New Balance: ₹%.2f",
                         (double)amount_cents / 100.0, (double)acc.balance_cents / 100.0);
                send_response(client_fd, resp);
            }
            /* --- WITHDRAW --- */
            else if (strcmp(cmd, "WITHDRAW") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: WITHDRAW|amount_cents");
                    continue;
                }
                int64_t amount_cents = atoll(args[1]);
                if (amount_cents <= 0) {
                    send_response(client_fd, "ERROR|INVALID_AMOUNT|Withdrawal amount must be positive.");
                    continue;
                }

                lock_bank_exclusive();
                User u;
                get_user_by_id(user_id, &u);
                if (strcmp(u.account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_FROZEN);
                    continue;
                }
                if (u.active == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_DEACTIVATED);
                    continue;
                }

                Account acc;
                if (get_account_by_user_id(user_id, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Account not found.");
                    continue;
                }

                if (acc.balance_cents < amount_cents) {
                    unlock_bank();
                    send_response(client_fd, ERR_INSUFFICIENT_FUNDS);
                    continue;
                }

                acc.balance_cents -= amount_cents;
                update_account(&acc);

                Transaction tx;
                memset(&tx, 0, sizeof(tx));
                tx.account_id = acc.account_id;
                strcpy(tx.type, TX_WITHDRAW_STR);
                tx.amount_cents = amount_cents;
                tx.related_account_id = 0;
                strcpy(tx.details, "Cash withdrawal");
                tx.timestamp = time(NULL);
                add_transaction(&tx);

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Withdrew ₹%.2f successfully. New Balance: ₹%.2f",
                         (double)amount_cents / 100.0, (double)acc.balance_cents / 100.0);
                send_response(client_fd, resp);
            }
            /* --- TRANSFER --- */
            else if (strcmp(cmd, "TRANSFER") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: TRANSFER|receiver_account_id|amount_cents");
                    continue;
                }
                int receiver_account_id = atoi(args[1]);
                int64_t amount_cents = atoll(args[2]);

                if (amount_cents <= 0) {
                    send_response(client_fd, "ERROR|INVALID_AMOUNT|Transfer amount must be positive.");
                    continue;
                }

                lock_bank_exclusive();
                User sender_u;
                get_user_by_id(user_id, &sender_u);
                if (strcmp(sender_u.account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_FROZEN);
                    continue;
                }
                if (sender_u.active == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_DEACTIVATED);
                    continue;
                }

                Account sender_acc;
                if (get_account_by_user_id(user_id, &sender_acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Sender account not found.");
                    continue;
                }

                if (sender_acc.account_id == receiver_account_id) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|INVALID_RECEIVER|Cannot transfer money to your own account.");
                    continue;
                }

                Account receiver_acc;
                if (get_account_by_id(receiver_account_id, &receiver_acc) != 0 || receiver_acc.active == 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Receiver account not found or inactive.");
                    continue;
                }

                User receiver_u;
                if (get_user_by_id(receiver_acc.user_id, &receiver_u) != 0 || receiver_u.active == 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Receiver user not found or inactive.");
                    continue;
                }
                if (strcmp(receiver_u.account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|RECEIVER_FROZEN|Receiver account is currently frozen and cannot accept transfers.");
                    continue;
                }

                if (sender_acc.balance_cents < amount_cents) {
                    unlock_bank();
                    send_response(client_fd, ERR_INSUFFICIENT_FUNDS);
                    continue;
                }

                // Check anomaly monitoring
                AnomalyResult anom;
                time_t now = time(NULL);
                if (detect_transfer_anomaly(sender_acc.account_id, receiver_acc.account_id, amount_cents, now, &anom)) {
                    int alert_id = 0;
                    create_anomaly_alert(&anom, &alert_id);
                    freeze_transfer_parties(sender_acc.account_id, receiver_acc.account_id, alert_id, anom.reason);
                    unlock_bank();

                    // Reject the current transfer and notify customer
                    send_response(client_fd, ERR_ACCOUNT_FROZEN);
                    continue;
                }

                // Normal transfer execution
                sender_acc.balance_cents -= amount_cents;
                receiver_acc.balance_cents += amount_cents;
                update_account(&sender_acc);
                update_account(&receiver_acc);

                Transaction tx_out;
                memset(&tx_out, 0, sizeof(tx_out));
                tx_out.account_id = sender_acc.account_id;
                strcpy(tx_out.type, TX_TRANSFER_OUT_STR);
                tx_out.amount_cents = amount_cents;
                tx_out.related_account_id = receiver_acc.account_id;
                snprintf(tx_out.details, sizeof(tx_out.details), "Transfer to Acc #%d (%s)", receiver_acc.account_id, receiver_u.username);
                tx_out.timestamp = now;
                add_transaction(&tx_out);

                Transaction tx_in;
                memset(&tx_in, 0, sizeof(tx_in));
                tx_in.account_id = receiver_acc.account_id;
                strcpy(tx_in.type, TX_TRANSFER_IN_STR);
                tx_in.amount_cents = amount_cents;
                tx_in.related_account_id = sender_acc.account_id;
                snprintf(tx_in.details, sizeof(tx_in.details), "Transfer from Acc #%d (%s)", sender_acc.account_id, sender_u.username);
                tx_in.timestamp = now;
                add_transaction(&tx_in);

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Transferred ₹%.2f to Acc #%d (%s). New Balance: ₹%.2f",
                         (double)amount_cents / 100.0, receiver_acc.account_id, receiver_u.username,
                         (double)sender_acc.balance_cents / 100.0);
                send_response(client_fd, resp);
            }
            /* --- APPLY_LOAN --- */
            else if (strcmp(cmd, "APPLY_LOAN") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: APPLY_LOAN|amount_cents");
                    continue;
                }
                int64_t amount_cents = atoll(args[1]);
                if (amount_cents <= 0) {
                    send_response(client_fd, "ERROR|INVALID_AMOUNT|Loan amount must be positive.");
                    continue;
                }

                lock_bank_exclusive();
                User u;
                get_user_by_id(user_id, &u);
                if (strcmp(u.account_status, STATUS_FROZEN_ANOMALY_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, ERR_ACCOUNT_FROZEN);
                    continue;
                }

                Account acc;
                if (get_account_by_user_id(user_id, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Account not found.");
                    continue;
                }

                Loan loan;
                memset(&loan, 0, sizeof(loan));
                loan.account_id = acc.account_id;
                loan.amount_cents = amount_cents;
                strcpy(loan.status, LOAN_PENDING_STR);
                loan.assigned_employee_id = 0;
                loan.created_at = time(NULL);
                loan.processed_at = 0;
                add_loan(&loan);

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Loan application #%d for ₹%.2f submitted. Awaiting manager assignment.",
                         loan.loan_id, (double)amount_cents / 100.0);
                send_response(client_fd, resp);
            }
            /* --- VIEW_HISTORY --- */
            else if (strcmp(cmd, "VIEW_HISTORY") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                lock_bank_shared();
                Account acc;
                if (get_account_by_user_id(user_id, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Account not found.");
                    continue;
                }

                Transaction *txs = NULL;
                int count = 0;
                get_transactions_by_account(acc.account_id, &txs, &count);
                unlock_bank();

                char resp[BUFFER_SIZE];
                size_t offset = 0;
                offset += snprintf(resp + offset, sizeof(resp) - offset,
                                   "SUCCESS|=== TRANSACTION PASSBOOK (Acc #%d) ===\n"
                                   "TX_ID | Type | Amount (₹) | Related Acc | Details | Timestamp\n"
                                   "----------------------------------------------------------------------\n",
                                   acc.account_id);

                for (int i = 0; i < count; i++) {
                    char time_str[32];
                    struct tm *tm_info = localtime(&txs[i].timestamp);
                    if (tm_info) strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                    else strcpy(time_str, "N/A");

                    offset += snprintf(resp + offset, sizeof(resp) - offset,
                                       "#%d | %s | ₹%.2f | Acc #%d | %s | %s\n",
                                       txs[i].transaction_id,
                                       txs[i].type,
                                       (double)txs[i].amount_cents / 100.0,
                                       txs[i].related_account_id,
                                       txs[i].details,
                                       time_str);
                    if (offset >= sizeof(resp) - 100) break;
                }
                if (count == 0) {
                    offset += snprintf(resp + offset, sizeof(resp) - offset, "No transactions found.\n");
                }
                free(txs);
                send_response(client_fd, resp);
            }
            /* --- ADD_FEEDBACK --- */
            else if (strcmp(cmd, "ADD_FEEDBACK") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: ADD_FEEDBACK|message");
                    continue;
                }
                Feedback fb;
                memset(&fb, 0, sizeof(fb));
                fb.user_id = user_id;
                strncpy(fb.message, args[1], sizeof(fb.message) - 1);
                fb.timestamp = time(NULL);

                lock_bank_exclusive();
                add_feedback(&fb);
                unlock_bank();

                send_response(client_fd, "SUCCESS|Thank you! Your feedback has been submitted to the manager.");
            }
            /* --- CHANGE_PASSWORD --- */
            else if (strcmp(cmd, "CHANGE_PASSWORD") == 0) {
                if (user_id <= 0) {
                    send_response(client_fd, ERR_NOT_LOGGED_IN);
                    continue;
                }
                if (argc < 2 || strlen(args[1]) == 0) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|New password cannot be empty.");
                    continue;
                }

                lock_bank_exclusive();
                User u;
                if (get_user_by_id(user_id, &u) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|User not found.");
                    continue;
                }
                sha256_hash_string(args[1], u.password_hash);
                update_user(&u);
                unlock_bank();

                send_response(client_fd, "SUCCESS|Your password has been changed successfully.");
            }
            /* --- ADD_CUSTOMER (Employee or Admin) --- */
            else if (strcmp(cmd, "ADD_CUSTOMER") == 0) {
                if (user_id <= 0 || (strcmp(role, ROLE_EMPLOYEE_STR) != 0 && strcmp(role, ROLE_ADMIN_STR) != 0)) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 4) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: ADD_CUSTOMER|username|password|initial_balance_cents");
                    continue;
                }
                const char *c_user = args[1];
                const char *c_pass = args[2];
                int64_t init_bal = atoll(args[3]);
                if (init_bal < 0) {
                    send_response(client_fd, "ERROR|INVALID_AMOUNT|Initial balance cannot be negative.");
                    continue;
                }

                lock_bank_exclusive();
                User u;
                memset(&u, 0, sizeof(u));
                strncpy(u.username, c_user, sizeof(u.username) - 1);
                sanitize_text(u.username);
                sha256_hash_string(c_pass, u.password_hash);
                strcpy(u.role, ROLE_CUSTOMER_STR);
                u.active = 1;
                strcpy(u.account_status, STATUS_ACTIVE_STR);

                int res = add_user(&u);
                if (res == -2) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|USERNAME_TAKEN|Username already exists.");
                    continue;
                } else if (res != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|STORAGE_ERROR|Failed to create customer.");
                    continue;
                }

                Account acc;
                memset(&acc, 0, sizeof(acc));
                acc.user_id = u.user_id;
                acc.balance_cents = init_bal;
                acc.active = 1;
                add_account(&acc);

                if (init_bal > 0) {
                    Transaction tx;
                    memset(&tx, 0, sizeof(tx));
                    tx.account_id = acc.account_id;
                    strcpy(tx.type, TX_DEPOSIT_STR);
                    tx.amount_cents = init_bal;
                    tx.related_account_id = 0;
                    strcpy(tx.details, "Account creation deposit");
                    tx.timestamp = time(NULL);
                    add_transaction(&tx);
                }

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Customer '%s' (User ID: %d) created with Account #%d and balance ₹%.2f.",
                         u.username, u.user_id, acc.account_id, (double)init_bal / 100.0);
                send_response(client_fd, resp);
            }
            /* --- VIEW_PASSBOOK (Employee, Manager, Admin) --- */
            else if (strcmp(cmd, "VIEW_PASSBOOK") == 0) {
                if (user_id <= 0 || (strcmp(role, ROLE_EMPLOYEE_STR) != 0 && strcmp(role, ROLE_MANAGER_STR) != 0 && strcmp(role, ROLE_ADMIN_STR) != 0)) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: VIEW_PASSBOOK|customer_user_id");
                    continue;
                }
                int cust_uid = atoi(args[1]);

                lock_bank_shared();
                User cu;
                if (get_user_by_id(cust_uid, &cu) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Customer user not found.");
                    continue;
                }

                Account acc;
                if (get_account_by_user_id(cust_uid, &acc) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Customer account not found.");
                    continue;
                }

                Transaction *txs = NULL;
                int count = 0;
                get_transactions_by_account(acc.account_id, &txs, &count);
                unlock_bank();

                char resp[BUFFER_SIZE];
                size_t offset = 0;
                offset += snprintf(resp + offset, sizeof(resp) - offset,
                                   "SUCCESS|=== PASSBOOK FOR %s (User ID #%d, Acc #%d, Bal ₹%.2f, Status: %s) ===\n"
                                   "TX_ID | Type | Amount (₹) | Related Acc | Details | Timestamp\n"
                                   "---------------------------------------------------------------------------------\n",
                                   cu.username, cu.user_id, acc.account_id, (double)acc.balance_cents / 100.0, cu.account_status);

                for (int i = 0; i < count; i++) {
                    char time_str[32];
                    struct tm *tm_info = localtime(&txs[i].timestamp);
                    if (tm_info) strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                    else strcpy(time_str, "N/A");

                    offset += snprintf(resp + offset, sizeof(resp) - offset,
                                       "#%d | %s | ₹%.2f | Acc #%d | %s | %s\n",
                                       txs[i].transaction_id,
                                       txs[i].type,
                                       (double)txs[i].amount_cents / 100.0,
                                       txs[i].related_account_id,
                                       txs[i].details,
                                       time_str);
                    if (offset >= sizeof(resp) - 100) break;
                }
                if (count == 0) {
                    offset += snprintf(resp + offset, sizeof(resp) - offset, "No transactions found.\n");
                }
                free(txs);
                send_response(client_fd, resp);
            }
            /* --- VIEW_ASSIGNED_LOANS (Employee) --- */
            else if (strcmp(cmd, "VIEW_ASSIGNED_LOANS") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_EMPLOYEE_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                lock_bank_shared();
                Loan *loans = NULL;
                int count = 0;
                get_all_loans(&loans, &count);
                unlock_bank();

                char resp[BUFFER_SIZE];
                size_t offset = 0;
                offset += snprintf(resp + offset, sizeof(resp) - offset,
                                   "SUCCESS|=== LOANS ASSIGNED TO YOU ===\n"
                                   "Loan ID | Account ID | Amount (₹) | Status | Applied At | Processed At\n"
                                   "----------------------------------------------------------------------\n");
                int assigned_count = 0;
                for (int i = 0; i < count; i++) {
                    if (loans[i].assigned_employee_id == user_id) {
                        assigned_count++;
                        char app_time[32] = "N/A", proc_time[32] = "N/A";
                        struct tm *tm_info = localtime(&loans[i].created_at);
                        if (tm_info) strftime(app_time, sizeof(app_time), "%Y-%m-%d %H:%M", tm_info);
                        if (loans[i].processed_at > 0) {
                            tm_info = localtime(&loans[i].processed_at);
                            if (tm_info) strftime(proc_time, sizeof(proc_time), "%Y-%m-%d %H:%M", tm_info);
                        }

                        offset += snprintf(resp + offset, sizeof(resp) - offset,
                                           "#%d | Acc #%d | ₹%.2f | %s | %s | %s\n",
                                           loans[i].loan_id,
                                           loans[i].account_id,
                                           (double)loans[i].amount_cents / 100.0,
                                           loans[i].status,
                                           app_time, proc_time);
                        if (offset >= sizeof(resp) - 100) break;
                    }
                }
                if (assigned_count == 0) {
                    offset += snprintf(resp + offset, sizeof(resp) - offset, "No loans currently assigned to you.\n");
                }
                free(loans);
                send_response(client_fd, resp);
            }
            /* --- PROCESS_LOAN (Employee) --- */
            else if (strcmp(cmd, "PROCESS_LOAN") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_EMPLOYEE_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: PROCESS_LOAN|loan_id|APPROVED/REJECTED");
                    continue;
                }
                int loan_id = atoi(args[1]);
                const char *decision = args[2];

                if (strcasecmp(decision, "APPROVED") != 0 && strcasecmp(decision, "REJECTED") != 0) {
                    send_response(client_fd, "ERROR|INVALID_DECISION|Decision must be APPROVED or REJECTED.");
                    continue;
                }

                lock_bank_exclusive();
                Loan loan;
                if (get_loan_by_id(loan_id, &loan) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Loan ID not found.");
                    continue;
                }

                if (loan.assigned_employee_id != user_id) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|UNAUTHORIZED|This loan is not assigned to you.");
                    continue;
                }

                if (strcmp(loan.status, LOAN_APPROVED_STR) == 0 || strcmp(loan.status, LOAN_REJECTED_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|ALREADY_PROCESSED|This loan has already been processed.");
                    continue;
                }

                if (strcasecmp(decision, "APPROVED") == 0) {
                    strcpy(loan.status, LOAN_APPROVED_STR);
                    loan.processed_at = time(NULL);
                    update_loan(&loan);

                    Account acc;
                    if (get_account_by_id(loan.account_id, &acc) == 0) {
                        acc.balance_cents += loan.amount_cents;
                        update_account(&acc);

                        Transaction tx;
                        memset(&tx, 0, sizeof(tx));
                        tx.account_id = acc.account_id;
                        strcpy(tx.type, TX_LOAN_CREDIT_STR);
                        tx.amount_cents = loan.amount_cents;
                        tx.related_account_id = 0;
                        snprintf(tx.details, sizeof(tx.details), "Loan #%d credited by Employee #%d", loan.loan_id, user_id);
                        tx.timestamp = time(NULL);
                        add_transaction(&tx);
                    }
                } else {
                    strcpy(loan.status, LOAN_REJECTED_STR);
                    loan.processed_at = time(NULL);
                    update_loan(&loan);
                }

                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Loan #%d has been %s.", loan.loan_id, loan.status);
                send_response(client_fd, resp);
            }
            /* --- ACTIVATE_ACCOUNT (Manager or Admin) --- */
            else if (strcmp(cmd, "ACTIVATE_ACCOUNT") == 0) {
                if (user_id <= 0 || (strcmp(role, ROLE_MANAGER_STR) != 0 && strcmp(role, ROLE_ADMIN_STR) != 0)) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: ACTIVATE_ACCOUNT|customer_user_id");
                    continue;
                }
                int target_uid = atoi(args[1]);

                lock_bank_exclusive();
                User target_u;
                if (get_user_by_id(target_uid, &target_u) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|User not found.");
                    continue;
                }

                target_u.active = 1;
                strcpy(target_u.account_status, STATUS_ACTIVE_STR);
                update_user(&target_u);

                Account acc;
                if (get_account_by_user_id(target_uid, &acc) == 0) {
                    acc.active = 1;
                    update_account(&acc);
                }
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|User '%s' (ID #%d) account is now ACTIVE.", target_u.username, target_uid);
                send_response(client_fd, resp);
            }
            /* --- DEACTIVATE_ACCOUNT (Manager or Admin) --- */
            else if (strcmp(cmd, "DEACTIVATE_ACCOUNT") == 0) {
                if (user_id <= 0 || (strcmp(role, ROLE_MANAGER_STR) != 0 && strcmp(role, ROLE_ADMIN_STR) != 0)) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: DEACTIVATE_ACCOUNT|customer_user_id");
                    continue;
                }
                int target_uid = atoi(args[1]);

                lock_bank_exclusive();
                User target_u;
                if (get_user_by_id(target_uid, &target_u) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|User not found.");
                    continue;
                }

                target_u.active = 0;
                strcpy(target_u.account_status, STATUS_DEACTIVATED_STR);
                update_user(&target_u);

                Account acc;
                if (get_account_by_user_id(target_uid, &acc) == 0) {
                    acc.active = 0;
                    update_account(&acc);
                }
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|User '%s' (ID #%d) account has been DEACTIVATED.", target_u.username, target_uid);
                send_response(client_fd, resp);
            }
            /* --- VIEW_PENDING_LOANS (Manager) --- */
            else if (strcmp(cmd, "VIEW_PENDING_LOANS") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                lock_bank_shared();
                Loan *loans = NULL;
                int count = 0;
                get_all_loans(&loans, &count);
                unlock_bank();

                char resp[BUFFER_SIZE];
                size_t offset = 0;
                offset += snprintf(resp + offset, sizeof(resp) - offset,
                                   "SUCCESS|=== PENDING LOAN APPLICATIONS ===\n"
                                   "Loan ID | Account ID | Amount (₹) | Status | Assigned Emp ID | Applied At\n"
                                   "-----------------------------------------------------------------------\n");
                int pending_count = 0;
                for (int i = 0; i < count; i++) {
                    if (strcmp(loans[i].status, LOAN_PENDING_STR) == 0 || strcmp(loans[i].status, LOAN_ASSIGNED_STR) == 0) {
                        pending_count++;
                        char app_time[32] = "N/A";
                        struct tm *tm_info = localtime(&loans[i].created_at);
                        if (tm_info) strftime(app_time, sizeof(app_time), "%Y-%m-%d %H:%M", tm_info);

                        offset += snprintf(resp + offset, sizeof(resp) - offset,
                                           "#%d | Acc #%d | ₹%.2f | %s | %d | %s\n",
                                           loans[i].loan_id,
                                           loans[i].account_id,
                                           (double)loans[i].amount_cents / 100.0,
                                           loans[i].status,
                                           loans[i].assigned_employee_id,
                                           app_time);
                        if (offset >= sizeof(resp) - 100) break;
                    }
                }
                if (pending_count == 0) {
                    offset += snprintf(resp + offset, sizeof(resp) - offset, "No pending or unassigned loans.\n");
                }
                free(loans);
                send_response(client_fd, resp);
            }
            /* --- ASSIGN_LOAN (Manager) --- */
            else if (strcmp(cmd, "ASSIGN_LOAN") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: ASSIGN_LOAN|loan_id|employee_id");
                    continue;
                }
                int loan_id = atoi(args[1]);
                int emp_id = atoi(args[2]);

                lock_bank_exclusive();
                User emp;
                if (get_user_by_id(emp_id, &emp) != 0 || strcmp(emp.role, ROLE_EMPLOYEE_STR) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Employee with specified ID does not exist.");
                    continue;
                }

                Loan loan;
                if (get_loan_by_id(loan_id, &loan) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Loan ID not found.");
                    continue;
                }

                if (strcmp(loan.status, LOAN_APPROVED_STR) == 0 || strcmp(loan.status, LOAN_REJECTED_STR) == 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|ALREADY_PROCESSED|Cannot assign an already processed loan.");
                    continue;
                }

                loan.assigned_employee_id = emp_id;
                strcpy(loan.status, LOAN_ASSIGNED_STR);
                update_loan(&loan);
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Loan #%d assigned to Employee '%s' (ID #%d).",
                         loan_id, emp.username, emp_id);
                send_response(client_fd, resp);
            }
            /* --- VIEW_FEEDBACK (Manager) --- */
            else if (strcmp(cmd, "VIEW_FEEDBACK") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                lock_bank_shared();
                Feedback *fbs = NULL;
                int count = 0;
                get_all_feedback(&fbs, &count);
                unlock_bank();

                char resp[BUFFER_SIZE];
                size_t offset = 0;
                offset += snprintf(resp + offset, sizeof(resp) - offset,
                                   "SUCCESS|=== CUSTOMER FEEDBACK ===\n"
                                   "ID | Customer User ID | Timestamp | Message\n"
                                   "----------------------------------------------------------------------\n");
                for (int i = 0; i < count; i++) {
                    char time_str[32] = "N/A";
                    struct tm *tm_info = localtime(&fbs[i].timestamp);
                    if (tm_info) strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                    offset += snprintf(resp + offset, sizeof(resp) - offset,
                                       "#%d | User #%d | %s | %s\n",
                                       fbs[i].feedback_id, fbs[i].user_id, time_str, fbs[i].message);
                    if (offset >= sizeof(resp) - 100) break;
                }
                if (count == 0) {
                    offset += snprintf(resp + offset, sizeof(resp) - offset, "No feedback submitted yet.\n");
                }
                free(fbs);
                send_response(client_fd, resp);
            }
            /* --- VIEW_ANOMALY_ALERTS (Manager) --- */
            else if (strcmp(cmd, "VIEW_ANOMALY_ALERTS") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                lock_bank_shared();
                char text[BUFFER_SIZE];
                list_open_anomaly_alerts(text, sizeof(text));
                unlock_bank();

                char resp[BUFFER_SIZE + 32];
                snprintf(resp, sizeof(resp), "SUCCESS|%s", text);
                send_response(client_fd, resp);
            }
            /* --- VIEW_FROZEN_ACCOUNTS (Manager) --- */
            else if (strcmp(cmd, "VIEW_FROZEN_ACCOUNTS") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                lock_bank_shared();
                char text[BUFFER_SIZE];
                list_frozen_accounts(text, sizeof(text));
                unlock_bank();

                char resp[BUFFER_SIZE + 32];
                snprintf(resp, sizeof(resp), "SUCCESS|%s", text);
                send_response(client_fd, resp);
            }
            /* --- VIEW_ANOMALY_DETAILS (Manager) --- */
            else if (strcmp(cmd, "VIEW_ANOMALY_DETAILS") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: VIEW_ANOMALY_DETAILS|alert_id");
                    continue;
                }
                int alert_id = atoi(args[1]);

                lock_bank_shared();
                char text[BUFFER_SIZE];
                if (get_anomaly_alert_details(alert_id, text, sizeof(text)) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|Alert ID not found.");
                    continue;
                }
                unlock_bank();

                char resp[BUFFER_SIZE + 32];
                snprintf(resp, sizeof(resp), "SUCCESS|%s", text);
                send_response(client_fd, resp);
            }
            /* --- RESOLVE_ANOMALY (Manager) --- */
            else if (strcmp(cmd, "RESOLVE_ANOMALY") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_MANAGER_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 2) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: RESOLVE_ANOMALY|alert_id|[resolution_note]");
                    continue;
                }
                int alert_id = atoi(args[1]);
                const char *note = (argc >= 3) ? args[2] : "Reviewed and unfrozen by manager";

                lock_bank_exclusive();
                int res = resolve_anomaly_alert(user_id, alert_id, note);
                unlock_bank();

                if (res == -1) {
                    send_response(client_fd, "ERROR|NOT_FOUND|Alert ID not found.");
                } else if (res == -2) {
                    send_response(client_fd, "ERROR|ALREADY_RESOLVED|This alert has already been resolved.");
                } else {
                    char resp[256];
                    snprintf(resp, sizeof(resp), "SUCCESS|Alert #%d resolved! Both sender and receiver accounts have been unfrozen.", alert_id);
                    send_response(client_fd, resp);
                }
            }
            /* --- ADD_EMPLOYEE (Admin) --- */
            else if (strcmp(cmd, "ADD_EMPLOYEE") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_ADMIN_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: ADD_EMPLOYEE|username|password");
                    continue;
                }
                const char *emp_name = args[1];
                const char *emp_pass = args[2];

                lock_bank_exclusive();
                User u;
                memset(&u, 0, sizeof(u));
                strncpy(u.username, emp_name, sizeof(u.username) - 1);
                sanitize_text(u.username);
                sha256_hash_string(emp_pass, u.password_hash);
                strcpy(u.role, ROLE_EMPLOYEE_STR);
                u.active = 1;
                strcpy(u.account_status, STATUS_ACTIVE_STR);

                int res = add_user(&u);
                unlock_bank();

                if (res == -2) {
                    send_response(client_fd, "ERROR|USERNAME_TAKEN|Username already exists.");
                } else if (res != 0) {
                    send_response(client_fd, "ERROR|STORAGE_ERROR|Failed to add employee.");
                } else {
                    char resp[256];
                    snprintf(resp, sizeof(resp), "SUCCESS|Bank Employee '%s' created with User ID #%d.", u.username, u.user_id);
                    send_response(client_fd, resp);
                }
            }
            /* --- MANAGE_ROLE (Admin) --- */
            else if (strcmp(cmd, "MANAGE_ROLE") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_ADMIN_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: MANAGE_ROLE|user_id|role");
                    continue;
                }
                int target_uid = atoi(args[1]);
                const char *new_role = args[2];

                if (strcasecmp(new_role, ROLE_CUSTOMER_STR) != 0 &&
                    strcasecmp(new_role, ROLE_EMPLOYEE_STR) != 0 &&
                    strcasecmp(new_role, ROLE_MANAGER_STR) != 0 &&
                    strcasecmp(new_role, ROLE_ADMIN_STR) != 0) {
                    send_response(client_fd, "ERROR|INVALID_ROLE|Role must be CUSTOMER, EMPLOYEE, MANAGER, or ADMIN.");
                    continue;
                }

                if (target_uid == user_id && strcasecmp(new_role, ROLE_ADMIN_STR) != 0) {
                    send_response(client_fd, "ERROR|CANNOT_DEMOTE_SELF|Admin cannot remove their own admin role.");
                    continue;
                }

                lock_bank_exclusive();
                User target_u;
                if (get_user_by_id(target_uid, &target_u) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|User not found.");
                    continue;
                }

                if (strcasecmp(new_role, ROLE_CUSTOMER_STR) == 0) strcpy(target_u.role, ROLE_CUSTOMER_STR);
                else if (strcasecmp(new_role, ROLE_EMPLOYEE_STR) == 0) strcpy(target_u.role, ROLE_EMPLOYEE_STR);
                else if (strcasecmp(new_role, ROLE_MANAGER_STR) == 0) strcpy(target_u.role, ROLE_MANAGER_STR);
                else if (strcasecmp(new_role, ROLE_ADMIN_STR) == 0) strcpy(target_u.role, ROLE_ADMIN_STR);

                update_user(&target_u);
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Role for '%s' (User ID #%d) updated to %s.",
                         target_u.username, target_uid, target_u.role);
                send_response(client_fd, resp);
            }
            /* --- ADMIN_RESET_PASSWORD (Admin) --- */
            else if (strcmp(cmd, "ADMIN_RESET_PASSWORD") == 0) {
                if (user_id <= 0 || strcmp(role, ROLE_ADMIN_STR) != 0) {
                    send_response(client_fd, ERR_UNAUTHORIZED);
                    continue;
                }
                if (argc < 3) {
                    send_response(client_fd, "ERROR|INVALID_ARGS|Usage: ADMIN_RESET_PASSWORD|user_id|new_password");
                    continue;
                }
                int target_uid = atoi(args[1]);
                const char *new_pass = args[2];

                lock_bank_exclusive();
                User target_u;
                if (get_user_by_id(target_uid, &target_u) != 0) {
                    unlock_bank();
                    send_response(client_fd, "ERROR|NOT_FOUND|User not found.");
                    continue;
                }

                sha256_hash_string(new_pass, target_u.password_hash);
                update_user(&target_u);
                unlock_bank();

                char resp[256];
                snprintf(resp, sizeof(resp), "SUCCESS|Password for '%s' (User ID #%d) reset successfully.",
                         target_u.username, target_uid);
                send_response(client_fd, resp);
            }
            /* --- UNKNOWN COMMAND --- */
            else {
                send_response(client_fd, "ERROR|UNKNOWN_COMMAND|The requested operation is not supported.");
            }
        }

        // Save leftover incomplete line
        if (strlen(line_start) > 0) {
            strncpy(leftover, line_start, sizeof(leftover) - 1);
            leftover[sizeof(leftover) - 1] = '\0';
        }
    }

    // Client disconnected
    if (user_id > 0) {
        release_session_lock(session_lock_fd, user_id);
    }
    close(client_fd);
    exit(0);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        port = atoi(argv[1]);
    }

    if (storage_init() != 0) {
        fprintf(stderr, "Failed to initialize storage!\n");
        return 1;
    }

    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 20) < 0) {
        perror("listen failed");
        close(server_fd);
        return 1;
    }

    printf("==================================================\n");
    printf("  BANKING MANAGEMENT SYSTEM SERVER RUNNING\n");
    printf("  Port: %d\n", port);
    printf("  Concurrency: Multi-client (Process-per-terminal)\n");
    printf("  Storage: Text-file DB with OS file locking\n");
    printf("  Anomaly Monitor: Active (3x same-amount in 60s)\n");
    printf("==================================================\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept error");
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            // Child process handles client
            close(server_fd);
            handle_client(client_fd);
        } else if (pid > 0) {
            // Parent closes connected socket
            close(client_fd);
        } else {
            perror("fork failed");
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}
