#define _GNU_SOURCE
#include "storage.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

static int g_bank_lock_fd = -1;

void sanitize_text(char *str) {
    if (!str) return;
    for (char *p = str; *p; p++) {
        if (*p == '|' || *p == '\n' || *p == '\r') {
            *p = ' ';
        }
    }
}

static int split_pipes(char *line, char **fields, int max_fields) {
    int count = 0;
    char *p = line;
    // Strip trailing \r and \n
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[len - 1] = '\0';
        len--;
    }

    fields[count++] = p;
    while (*p && count < max_fields) {
        if (*p == '|') {
            *p = '\0';
            fields[count++] = p + 1;
        }
        p++;
    }
    return count;
}

int storage_init(void) {
    mkdir("data", 0755);
    mkdir("data/sessions", 0755);

    g_bank_lock_fd = open(BANK_LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (g_bank_lock_fd < 0) {
        perror("storage_init: failed to open bank.lock");
        return -1;
    }

    seed_initial_data_if_needed();
    return 0;
}

int lock_bank_shared(void) {
    if (g_bank_lock_fd < 0) return -1;
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    return fcntl(g_bank_lock_fd, F_SETLKW, &fl);
}

int lock_bank_exclusive(void) {
    if (g_bank_lock_fd < 0) return -1;
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    return fcntl(g_bank_lock_fd, F_SETLKW, &fl);
}

int unlock_bank(void) {
    if (g_bank_lock_fd < 0) return -1;
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    return fcntl(g_bank_lock_fd, F_SETLKW, &fl);
}

int acquire_session_lock(int user_id) {
    char path[256];
    snprintf(path, sizeof(path), "data/sessions/%d.lock", user_id);
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return -1;

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        close(fd);
        return -1; // already locked by another process
    }
    return fd;
}

void release_session_lock(int fd, int user_id) {
    (void)user_id;
    if (fd >= 0) {
        struct flock fl;
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
    }
}

/* User Functions */
int get_all_users(User **users_out, int *count_out) {
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) {
        *users_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    User *users = malloc(capacity * sizeof(User));
    if (!users) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[6];
        int nf = split_pipes(line, fields, 6);
        if (nf >= 6) {
            if (count >= capacity) {
                capacity *= 2;
                User *tmp = realloc(users, capacity * sizeof(User));
                if (!tmp) {
                    free(users);
                    fclose(fp);
                    return -1;
                }
                users = tmp;
            }
            users[count].user_id = atoi(fields[0]);
            strncpy(users[count].username, fields[1], sizeof(users[count].username) - 1);
            users[count].username[sizeof(users[count].username) - 1] = '\0';
            strncpy(users[count].password_hash, fields[2], sizeof(users[count].password_hash) - 1);
            users[count].password_hash[sizeof(users[count].password_hash) - 1] = '\0';
            strncpy(users[count].role, fields[3], sizeof(users[count].role) - 1);
            users[count].role[sizeof(users[count].role) - 1] = '\0';
            users[count].active = atoi(fields[4]);
            strncpy(users[count].account_status, fields[5], sizeof(users[count].account_status) - 1);
            users[count].account_status[sizeof(users[count].account_status) - 1] = '\0';
            count++;
        }
    }
    fclose(fp);
    *users_out = users;
    *count_out = count;
    return 0;
}

static int save_all_users(User *users, int count) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", USERS_FILE, getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;

    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d|%s|%s|%s|%d|%s\n",
                users[i].user_id,
                users[i].username,
                users[i].password_hash,
                users[i].role,
                users[i].active,
                users[i].account_status);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    if (rename(tmp_path, USERS_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int get_user_by_id(int user_id, User *user) {
    User *users = NULL;
    int count = 0;
    if (get_all_users(&users, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (users[i].user_id == user_id) {
            if (user) *user = users[i];
            found = 1;
            break;
        }
    }
    free(users);
    return found ? 0 : -1;
}

int get_user_by_username(const char *username, User *user) {
    User *users = NULL;
    int count = 0;
    if (get_all_users(&users, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (user) *user = users[i];
            found = 1;
            break;
        }
    }
    free(users);
    return found ? 0 : -1;
}

int add_user(User *user) {
    User *users = NULL;
    int count = 0;
    if (get_all_users(&users, &count) != 0) return -1;

    // Determine next id
    int max_id = 0;
    for (int i = 0; i < count; i++) {
        if (users[i].user_id > max_id) max_id = users[i].user_id;
        if (strcmp(users[i].username, user->username) == 0) {
            free(users);
            return -2; // Username already exists
        }
    }
    user->user_id = max_id + 1;

    User *new_users = realloc(users, (count + 1) * sizeof(User));
    if (!new_users) {
        free(users);
        return -1;
    }
    new_users[count] = *user;
    int res = save_all_users(new_users, count + 1);
    free(new_users);
    return res;
}

int update_user(const User *user) {
    User *users = NULL;
    int count = 0;
    if (get_all_users(&users, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (users[i].user_id == user->user_id) {
            users[i] = *user;
            found = 1;
            break;
        }
    }
    if (!found) {
        free(users);
        return -1;
    }
    int res = save_all_users(users, count);
    free(users);
    return res;
}

/* Account Functions */
int get_all_accounts(Account **accounts_out, int *count_out) {
    FILE *fp = fopen(ACCOUNTS_FILE, "r");
    if (!fp) {
        *accounts_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Account *accounts = malloc(capacity * sizeof(Account));
    if (!accounts) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[4];
        int nf = split_pipes(line, fields, 4);
        if (nf >= 4) {
            if (count >= capacity) {
                capacity *= 2;
                Account *tmp = realloc(accounts, capacity * sizeof(Account));
                if (!tmp) {
                    free(accounts);
                    fclose(fp);
                    return -1;
                }
                accounts = tmp;
            }
            accounts[count].account_id = atoi(fields[0]);
            accounts[count].user_id = atoi(fields[1]);
            accounts[count].balance_cents = atoll(fields[2]);
            accounts[count].active = atoi(fields[3]);
            count++;
        }
    }
    fclose(fp);
    *accounts_out = accounts;
    *count_out = count;
    return 0;
}

static int save_all_accounts(Account *accounts, int count) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", ACCOUNTS_FILE, getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;

    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d|%d|%lld|%d\n",
                accounts[i].account_id,
                accounts[i].user_id,
                (long long)accounts[i].balance_cents,
                accounts[i].active);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    if (rename(tmp_path, ACCOUNTS_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int get_account_by_id(int account_id, Account *account) {
    Account *accounts = NULL;
    int count = 0;
    if (get_all_accounts(&accounts, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (accounts[i].account_id == account_id) {
            if (account) *account = accounts[i];
            found = 1;
            break;
        }
    }
    free(accounts);
    return found ? 0 : -1;
}

int get_account_by_user_id(int user_id, Account *account) {
    Account *accounts = NULL;
    int count = 0;
    if (get_all_accounts(&accounts, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (accounts[i].user_id == user_id) {
            if (account) *account = accounts[i];
            found = 1;
            break;
        }
    }
    free(accounts);
    return found ? 0 : -1;
}

int add_account(Account *account) {
    Account *accounts = NULL;
    int count = 0;
    if (get_all_accounts(&accounts, &count) != 0) return -1;

    int max_id = 0;
    for (int i = 0; i < count; i++) {
        if (accounts[i].account_id > max_id) max_id = accounts[i].account_id;
    }
    account->account_id = max_id + 1;

    Account *new_accounts = realloc(accounts, (count + 1) * sizeof(Account));
    if (!new_accounts) {
        free(accounts);
        return -1;
    }
    new_accounts[count] = *account;
    int res = save_all_accounts(new_accounts, count + 1);
    free(new_accounts);
    return res;
}

int update_account(const Account *account) {
    Account *accounts = NULL;
    int count = 0;
    if (get_all_accounts(&accounts, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (accounts[i].account_id == account->account_id) {
            accounts[i] = *account;
            found = 1;
            break;
        }
    }
    if (!found) {
        free(accounts);
        return -1;
    }
    int res = save_all_accounts(accounts, count);
    free(accounts);
    return res;
}

/* Transaction Functions */
int add_transaction(Transaction *tx) {
    FILE *fp = fopen(TRANSACTIONS_FILE, "r");
    int max_id = 0;
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            char *fields[7];
            if (split_pipes(line, fields, 7) >= 1) {
                int tid = atoi(fields[0]);
                if (tid > max_id) max_id = tid;
            }
        }
        fclose(fp);
    }

    tx->transaction_id = max_id + 1;
    if (tx->timestamp == 0) tx->timestamp = time(NULL);

    sanitize_text(tx->details);

    fp = fopen(TRANSACTIONS_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%d|%d|%s|%lld|%d|%s|%ld\n",
            tx->transaction_id,
            tx->account_id,
            tx->type,
            (long long)tx->amount_cents,
            tx->related_account_id,
            tx->details,
            (long)tx->timestamp);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return 0;
}

int get_transactions_by_account(int account_id, Transaction **txs_out, int *count_out) {
    FILE *fp = fopen(TRANSACTIONS_FILE, "r");
    if (!fp) {
        *txs_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Transaction *txs = malloc(capacity * sizeof(Transaction));
    if (!txs) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[7];
        int nf = split_pipes(line, fields, 7);
        if (nf >= 7) {
            int acc_id = atoi(fields[1]);
            if (acc_id == account_id) {
                if (count >= capacity) {
                    capacity *= 2;
                    Transaction *tmp = realloc(txs, capacity * sizeof(Transaction));
                    if (!tmp) {
                        free(txs);
                        fclose(fp);
                        return -1;
                    }
                    txs = tmp;
                }
                txs[count].transaction_id = atoi(fields[0]);
                txs[count].account_id = acc_id;
                strncpy(txs[count].type, fields[2], sizeof(txs[count].type) - 1);
                txs[count].type[sizeof(txs[count].type) - 1] = '\0';
                txs[count].amount_cents = atoll(fields[3]);
                txs[count].related_account_id = atoi(fields[4]);
                strncpy(txs[count].details, fields[5], sizeof(txs[count].details) - 1);
                txs[count].details[sizeof(txs[count].details) - 1] = '\0';
                txs[count].timestamp = (time_t)atol(fields[6]);
                count++;
            }
        }
    }
    fclose(fp);
    *txs_out = txs;
    *count_out = count;
    return 0;
}

int get_recent_sender_transfers(int sender_account_id, time_t since_time, Transaction **txs_out, int *count_out) {
    FILE *fp = fopen(TRANSACTIONS_FILE, "r");
    if (!fp) {
        *txs_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Transaction *txs = malloc(capacity * sizeof(Transaction));
    if (!txs) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[7];
        int nf = split_pipes(line, fields, 7);
        if (nf >= 7) {
            int acc_id = atoi(fields[1]);
            const char *type = fields[2];
            time_t t = (time_t)atol(fields[6]);
            if (acc_id == sender_account_id && strcmp(type, TX_TRANSFER_OUT_STR) == 0 && t >= since_time) {
                if (count >= capacity) {
                    capacity *= 2;
                    Transaction *tmp = realloc(txs, capacity * sizeof(Transaction));
                    if (!tmp) {
                        free(txs);
                        fclose(fp);
                        return -1;
                    }
                    txs = tmp;
                }
                txs[count].transaction_id = atoi(fields[0]);
                txs[count].account_id = acc_id;
                strncpy(txs[count].type, type, sizeof(txs[count].type) - 1);
                txs[count].type[sizeof(txs[count].type) - 1] = '\0';
                txs[count].amount_cents = atoll(fields[3]);
                txs[count].related_account_id = atoi(fields[4]);
                strncpy(txs[count].details, fields[5], sizeof(txs[count].details) - 1);
                txs[count].details[sizeof(txs[count].details) - 1] = '\0';
                txs[count].timestamp = t;
                count++;
            }
        }
    }
    fclose(fp);
    *txs_out = txs;
    *count_out = count;
    return 0;
}

/* Loan Functions */
int get_all_loans(Loan **loans_out, int *count_out) {
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) {
        *loans_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Loan *loans = malloc(capacity * sizeof(Loan));
    if (!loans) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[7];
        int nf = split_pipes(line, fields, 7);
        if (nf >= 7) {
            if (count >= capacity) {
                capacity *= 2;
                Loan *tmp = realloc(loans, capacity * sizeof(Loan));
                if (!tmp) {
                    free(loans);
                    fclose(fp);
                    return -1;
                }
                loans = tmp;
            }
            loans[count].loan_id = atoi(fields[0]);
            loans[count].account_id = atoi(fields[1]);
            loans[count].amount_cents = atoll(fields[2]);
            strncpy(loans[count].status, fields[3], sizeof(loans[count].status) - 1);
            loans[count].status[sizeof(loans[count].status) - 1] = '\0';
            loans[count].assigned_employee_id = atoi(fields[4]);
            loans[count].created_at = (time_t)atol(fields[5]);
            loans[count].processed_at = (time_t)atol(fields[6]);
            count++;
        }
    }
    fclose(fp);
    *loans_out = loans;
    *count_out = count;
    return 0;
}

static int save_all_loans(Loan *loans, int count) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", LOANS_FILE, getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;

    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d|%d|%lld|%s|%d|%ld|%ld\n",
                loans[i].loan_id,
                loans[i].account_id,
                (long long)loans[i].amount_cents,
                loans[i].status,
                loans[i].assigned_employee_id,
                (long)loans[i].created_at,
                (long)loans[i].processed_at);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    if (rename(tmp_path, LOANS_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int get_loan_by_id(int loan_id, Loan *loan) {
    Loan *loans = NULL;
    int count = 0;
    if (get_all_loans(&loans, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (loans[i].loan_id == loan_id) {
            if (loan) *loan = loans[i];
            found = 1;
            break;
        }
    }
    free(loans);
    return found ? 0 : -1;
}

int add_loan(Loan *loan) {
    Loan *loans = NULL;
    int count = 0;
    if (get_all_loans(&loans, &count) != 0) return -1;

    int max_id = 0;
    for (int i = 0; i < count; i++) {
        if (loans[i].loan_id > max_id) max_id = loans[i].loan_id;
    }
    loan->loan_id = max_id + 1;
    if (loan->created_at == 0) loan->created_at = time(NULL);

    Loan *new_loans = realloc(loans, (count + 1) * sizeof(Loan));
    if (!new_loans) {
        free(loans);
        return -1;
    }
    new_loans[count] = *loan;
    int res = save_all_loans(new_loans, count + 1);
    free(new_loans);
    return res;
}

int update_loan(const Loan *loan) {
    Loan *loans = NULL;
    int count = 0;
    if (get_all_loans(&loans, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (loans[i].loan_id == loan->loan_id) {
            loans[i] = *loan;
            found = 1;
            break;
        }
    }
    if (!found) {
        free(loans);
        return -1;
    }
    int res = save_all_loans(loans, count);
    free(loans);
    return res;
}

/* Feedback Functions */
int get_all_feedback(Feedback **fbs_out, int *count_out) {
    FILE *fp = fopen(FEEDBACK_FILE, "r");
    if (!fp) {
        *fbs_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Feedback *fbs = malloc(capacity * sizeof(Feedback));
    if (!fbs) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[4];
        int nf = split_pipes(line, fields, 4);
        if (nf >= 4) {
            if (count >= capacity) {
                capacity *= 2;
                Feedback *tmp = realloc(fbs, capacity * sizeof(Feedback));
                if (!tmp) {
                    free(fbs);
                    fclose(fp);
                    return -1;
                }
                fbs = tmp;
            }
            fbs[count].feedback_id = atoi(fields[0]);
            fbs[count].user_id = atoi(fields[1]);
            strncpy(fbs[count].message, fields[2], sizeof(fbs[count].message) - 1);
            fbs[count].message[sizeof(fbs[count].message) - 1] = '\0';
            fbs[count].timestamp = (time_t)atol(fields[3]);
            count++;
        }
    }
    fclose(fp);
    *fbs_out = fbs;
    *count_out = count;
    return 0;
}

int add_feedback(Feedback *fb) {
    Feedback *fbs = NULL;
    int count = 0;
    get_all_feedback(&fbs, &count);
    int max_id = 0;
    for (int i = 0; i < count; i++) {
        if (fbs[i].feedback_id > max_id) max_id = fbs[i].feedback_id;
    }
    free(fbs);

    fb->feedback_id = max_id + 1;
    if (fb->timestamp == 0) fb->timestamp = time(NULL);
    sanitize_text(fb->message);

    FILE *fp = fopen(FEEDBACK_FILE, "a");
    if (!fp) return -1;
    fprintf(fp, "%d|%d|%s|%ld\n",
            fb->feedback_id,
            fb->user_id,
            fb->message,
            (long)fb->timestamp);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return 0;
}

/* Alert Functions */
int get_all_alerts(Alert **alerts_out, int *count_out) {
    FILE *fp = fopen(ALERTS_FILE, "r");
    if (!fp) {
        *alerts_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Alert *alerts = malloc(capacity * sizeof(Alert));
    if (!alerts) {
        fclose(fp);
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[13];
        int nf = split_pipes(line, fields, 13);
        if (nf >= 13) {
            if (count >= capacity) {
                capacity *= 2;
                Alert *tmp = realloc(alerts, capacity * sizeof(Alert));
                if (!tmp) {
                    free(alerts);
                    fclose(fp);
                    return -1;
                }
                alerts = tmp;
            }
            alerts[count].alert_id = atoi(fields[0]);
            strncpy(alerts[count].type, fields[1], sizeof(alerts[count].type) - 1);
            alerts[count].type[sizeof(alerts[count].type) - 1] = '\0';
            alerts[count].sender_account_id = atoi(fields[2]);
            alerts[count].receiver_account_id = atoi(fields[3]);
            alerts[count].amount_cents = atoll(fields[4]);
            alerts[count].count = atoi(fields[5]);
            alerts[count].window_seconds = atoi(fields[6]);
            strncpy(alerts[count].reason, fields[7], sizeof(alerts[count].reason) - 1);
            alerts[count].reason[sizeof(alerts[count].reason) - 1] = '\0';
            strncpy(alerts[count].status, fields[8], sizeof(alerts[count].status) - 1);
            alerts[count].status[sizeof(alerts[count].status) - 1] = '\0';
            alerts[count].created_at = (time_t)atol(fields[9]);
            alerts[count].resolved_by = atoi(fields[10]);
            alerts[count].resolved_at = (time_t)atol(fields[11]);
            strncpy(alerts[count].resolution_note, fields[12], sizeof(alerts[count].resolution_note) - 1);
            alerts[count].resolution_note[sizeof(alerts[count].resolution_note) - 1] = '\0';
            count++;
        }
    }
    fclose(fp);
    *alerts_out = alerts;
    *count_out = count;
    return 0;
}

static int save_all_alerts(Alert *alerts, int count) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", ALERTS_FILE, getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;

    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d|%s|%d|%d|%lld|%d|%d|%s|%s|%ld|%d|%ld|%s\n",
                alerts[i].alert_id,
                alerts[i].type,
                alerts[i].sender_account_id,
                alerts[i].receiver_account_id,
                (long long)alerts[i].amount_cents,
                alerts[i].count,
                alerts[i].window_seconds,
                alerts[i].reason,
                alerts[i].status,
                (long)alerts[i].created_at,
                alerts[i].resolved_by,
                (long)alerts[i].resolved_at,
                alerts[i].resolution_note);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    if (rename(tmp_path, ALERTS_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int get_alert_by_id(int alert_id, Alert *alert) {
    Alert *alerts = NULL;
    int count = 0;
    if (get_all_alerts(&alerts, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (alerts[i].alert_id == alert_id) {
            if (alert) *alert = alerts[i];
            found = 1;
            break;
        }
    }
    free(alerts);
    return found ? 0 : -1;
}

int add_alert(Alert *alert) {
    Alert *alerts = NULL;
    int count = 0;
    if (get_all_alerts(&alerts, &count) != 0) return -1;

    int max_id = 0;
    for (int i = 0; i < count; i++) {
        if (alerts[i].alert_id > max_id) max_id = alerts[i].alert_id;
    }
    alert->alert_id = max_id + 1;
    if (alert->created_at == 0) alert->created_at = time(NULL);
    sanitize_text(alert->reason);
    sanitize_text(alert->resolution_note);

    Alert *new_alerts = realloc(alerts, (count + 1) * sizeof(Alert));
    if (!new_alerts) {
        free(alerts);
        return -1;
    }
    new_alerts[count] = *alert;
    int res = save_all_alerts(new_alerts, count + 1);
    free(new_alerts);
    return res;
}

int update_alert(const Alert *alert) {
    Alert *alerts = NULL;
    int count = 0;
    if (get_all_alerts(&alerts, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (alerts[i].alert_id == alert->alert_id) {
            alerts[i] = *alert;
            sanitize_text(alerts[i].reason);
            sanitize_text(alerts[i].resolution_note);
            found = 1;
            break;
        }
    }
    if (!found) {
        free(alerts);
        return -1;
    }
    int res = save_all_alerts(alerts, count);
    free(alerts);
    return res;
}

/* Freeze Functions */
int get_all_freezes(Freeze **freezes_out, int *count_out) {
    FILE *fp = fopen(FREEZES_FILE, "r");
    if (!fp) {
        *freezes_out = NULL;
        *count_out = 0;
        return 0;
    }

    int capacity = 16;
    int count = 0;
    Freeze *freezes = malloc(capacity * sizeof(Freeze));
    if (!freezes) {
        fclose(fp);
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *fields[9];
        int nf = split_pipes(line, fields, 9);
        if (nf >= 9) {
            if (count >= capacity) {
                capacity *= 2;
                Freeze *tmp = realloc(freezes, capacity * sizeof(Freeze));
                if (!tmp) {
                    free(freezes);
                    fclose(fp);
                    return -1;
                }
                freezes = tmp;
            }
            freezes[count].freeze_id = atoi(fields[0]);
            freezes[count].account_id = atoi(fields[1]);
            freezes[count].alert_id = atoi(fields[2]);
            strncpy(freezes[count].status, fields[3], sizeof(freezes[count].status) - 1);
            freezes[count].status[sizeof(freezes[count].status) - 1] = '\0';
            strncpy(freezes[count].reason, fields[4], sizeof(freezes[count].reason) - 1);
            freezes[count].reason[sizeof(freezes[count].reason) - 1] = '\0';
            freezes[count].created_at = (time_t)atol(fields[5]);
            freezes[count].resolved_by = atoi(fields[6]);
            freezes[count].resolved_at = (time_t)atol(fields[7]);
            strncpy(freezes[count].resolution_note, fields[8], sizeof(freezes[count].resolution_note) - 1);
            freezes[count].resolution_note[sizeof(freezes[count].resolution_note) - 1] = '\0';
            count++;
        }
    }
    fclose(fp);
    *freezes_out = freezes;
    *count_out = count;
    return 0;
}

static int save_all_freezes(Freeze *freezes, int count) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", FREEZES_FILE, getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;

    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d|%d|%d|%s|%s|%ld|%d|%ld|%s\n",
                freezes[i].freeze_id,
                freezes[i].account_id,
                freezes[i].alert_id,
                freezes[i].status,
                freezes[i].reason,
                (long)freezes[i].created_at,
                freezes[i].resolved_by,
                (long)freezes[i].resolved_at,
                freezes[i].resolution_note);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    if (rename(tmp_path, FREEZES_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int add_freeze(Freeze *freeze) {
    Freeze *freezes = NULL;
    int count = 0;
    if (get_all_freezes(&freezes, &count) != 0) return -1;

    int max_id = 0;
    for (int i = 0; i < count; i++) {
        if (freezes[i].freeze_id > max_id) max_id = freezes[i].freeze_id;
    }
    freeze->freeze_id = max_id + 1;
    if (freeze->created_at == 0) freeze->created_at = time(NULL);
    sanitize_text(freeze->reason);
    sanitize_text(freeze->resolution_note);

    Freeze *new_freezes = realloc(freezes, (count + 1) * sizeof(Freeze));
    if (!new_freezes) {
        free(freezes);
        return -1;
    }
    new_freezes[count] = *freeze;
    int res = save_all_freezes(new_freezes, count + 1);
    free(new_freezes);
    return res;
}

int update_freeze(const Freeze *freeze) {
    Freeze *freezes = NULL;
    int count = 0;
    if (get_all_freezes(&freezes, &count) != 0) return -1;

    int found = 0;
    for (int i = 0; i < count; i++) {
        if (freezes[i].freeze_id == freeze->freeze_id) {
            freezes[i] = *freeze;
            sanitize_text(freezes[i].reason);
            sanitize_text(freezes[i].resolution_note);
            found = 1;
            break;
        }
    }
    if (!found) {
        free(freezes);
        return -1;
    }
    int res = save_all_freezes(freezes, count);
    free(freezes);
    return res;
}

int get_active_freeze_by_account(int account_id, Freeze *freeze) {
    Freeze *freezes = NULL;
    int count = 0;
    if (get_all_freezes(&freezes, &count) != 0) return -1;

    int found = 0;
    for (int i = count - 1; i >= 0; i--) { // latest freeze first
        if (freezes[i].account_id == account_id && strcmp(freezes[i].status, FREEZE_FROZEN_STR) == 0) {
            if (freeze) *freeze = freezes[i];
            found = 1;
            break;
        }
    }
    free(freezes);
    return found ? 0 : -1;
}

/* Initial Data Seeding */
void seed_initial_data_if_needed(void) {
    // If users.txt does not exist or is empty, create initial accounts
    FILE *fp = fopen(USERS_FILE, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fclose(fp);
        if (sz > 0) return; // already seeded
    }

    // Seed Users
    User users[5];
    memset(users, 0, sizeof(users));

    // Admin
    users[0].user_id = 1;
    strcpy(users[0].username, "admin");
    sha256_hash_string("admin123", users[0].password_hash);
    strcpy(users[0].role, ROLE_ADMIN_STR);
    users[0].active = 1;
    strcpy(users[0].account_status, STATUS_ACTIVE_STR);

    // Manager
    users[1].user_id = 2;
    strcpy(users[1].username, "manager");
    sha256_hash_string("manager123", users[1].password_hash);
    strcpy(users[1].role, ROLE_MANAGER_STR);
    users[1].active = 1;
    strcpy(users[1].account_status, STATUS_ACTIVE_STR);

    // Employee
    users[2].user_id = 3;
    strcpy(users[2].username, "emp1");
    sha256_hash_string("emp123", users[2].password_hash);
    strcpy(users[2].role, ROLE_EMPLOYEE_STR);
    users[2].active = 1;
    strcpy(users[2].account_status, STATUS_ACTIVE_STR);

    // Customer 1: Alice
    users[3].user_id = 4;
    strcpy(users[3].username, "alice");
    sha256_hash_string("alice123", users[3].password_hash);
    strcpy(users[3].role, ROLE_CUSTOMER_STR);
    users[3].active = 1;
    strcpy(users[3].account_status, STATUS_ACTIVE_STR);

    // Customer 2: Bob
    users[4].user_id = 5;
    strcpy(users[4].username, "bob");
    sha256_hash_string("bob123", users[4].password_hash);
    strcpy(users[4].role, ROLE_CUSTOMER_STR);
    users[4].active = 1;
    strcpy(users[4].account_status, STATUS_ACTIVE_STR);

    save_all_users(users, 5);

    // Seed Accounts
    Account accounts[2];
    memset(accounts, 0, sizeof(accounts));

    accounts[0].account_id = 1;
    accounts[0].user_id = 4; // alice
    accounts[0].balance_cents = 100000; // Rs. 1000.00
    accounts[0].active = 1;

    accounts[1].account_id = 2;
    accounts[1].user_id = 5; // bob
    accounts[1].balance_cents = 50000; // Rs. 500.00
    accounts[1].active = 1;

    save_all_accounts(accounts, 2);

    // Seed initial deposit transactions
    Transaction t1;
    memset(&t1, 0, sizeof(t1));
    t1.account_id = 1;
    strcpy(t1.type, TX_DEPOSIT_STR);
    t1.amount_cents = 100000;
    t1.related_account_id = 0;
    strcpy(t1.details, "Initial balance deposit");
    t1.timestamp = time(NULL) - 300;
    add_transaction(&t1);

    Transaction t2;
    memset(&t2, 0, sizeof(t2));
    t2.account_id = 2;
    strcpy(t2.type, TX_DEPOSIT_STR);
    t2.amount_cents = 50000;
    t2.related_account_id = 0;
    strcpy(t2.details, "Initial balance deposit");
    t2.timestamp = time(NULL) - 300;
    add_transaction(&t2);
}
