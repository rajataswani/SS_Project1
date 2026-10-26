#define _GNU_SOURCE
#include "models.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_BOLD    "\033[1m"

static int g_sock = -1;

static void read_string(const char *prompt, char *dest, size_t max_len) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(dest, max_len, stdin) != NULL) {
        size_t len = strlen(dest);
        while (len > 0 && (dest[len - 1] == '\n' || dest[len - 1] == '\r')) {
            dest[len - 1] = '\0';
            len--;
        }
    } else {
        dest[0] = '\0';
    }
}

static int64_t read_money_cents(const char *prompt) {
    char buf[64];
    read_string(prompt, buf, sizeof(buf));
    double val = atof(buf);
    if (val <= 0.0) return -1;
    return (int64_t)(val * 100.0 + 0.5);
}

static int send_command(const char *cmd, char *response, size_t resp_size) {
    if (g_sock < 0) return -1;
    if (write(g_sock, cmd, strlen(cmd)) < 0) return -1;
    if (write(g_sock, "\n", 1) < 0) return -1;

    ssize_t n = read(g_sock, response, resp_size - 1);
    if (n <= 0) {
        printf(COLOR_RED "\n[Disconnected from server]\n" COLOR_RESET);
        return -1;
    }
    response[n] = '\0';
    size_t len = strlen(response);
    while (len > 0 && (response[len - 1] == '\n' || response[len - 1] == '\r')) {
        response[len - 1] = '\0';
        len--;
    }
    return 0;
}

static void print_banner(void) {
    printf("\n" COLOR_CYAN);
    printf("=========================================================\n");
    printf("        BANKING MANAGEMENT & SECURITY SYSTEM CLI        \n");
    printf("=========================================================\n" COLOR_RESET);
}

static void display_freeze_alert(const char *message) {
    printf("\n" COLOR_RED);
    printf("*********************************************************\n");
    printf("                  !!! ACCOUNT FROZEN !!!                 \n");
    printf("*********************************************************\n" COLOR_RESET);
    printf(COLOR_YELLOW "Reason: %s\n" COLOR_RESET, message);
    printf(COLOR_BOLD "Notice: All financial transactions (Deposits, Withdrawals,\n"
                      "Transfers, and Loan applications) are BLOCKED.\n"
                      "You can still view your balance and transaction history.\n"
                      "Please contact a Bank Manager to review and unfreeze.\n" COLOR_RESET);
    printf(COLOR_RED "*********************************************************\n\n" COLOR_RESET);
}

static void handle_customer_menu(const char *username) {
    while (1) {
        printf("\n" COLOR_BLUE "=== CUSTOMER DASHBOARD [%s] ===" COLOR_RESET "\n", username);
        printf("1. View Balance\n");
        printf("2. Deposit Money\n");
        printf("3. Withdraw Money\n");
        printf("4. Transfer Money (Send to another account)\n");
        printf("5. Apply for a Loan\n");
        printf("6. View Transaction Passbook\n");
        printf("7. Submit Feedback to Bank\n");
        printf("8. Change Password\n");
        printf("9. Logout\n");

        char choice[16];
        read_string(COLOR_CYAN "Choose an option (1-9): " COLOR_RESET, choice, sizeof(choice));
        int c = atoi(choice);

        char resp[BUFFER_SIZE];
        if (c == 1) {
            if (send_command("VIEW_BALANCE", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 2) {
            int64_t cents = read_money_cents("Enter deposit amount (₹): ");
            if (cents <= 0) {
                printf(COLOR_RED "Invalid amount. Must be positive.\n" COLOR_RESET);
                continue;
            }
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "DEPOSIT|%lld", (long long)cents);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else if (strstr(resp, "ACCOUNT_FROZEN")) {
                    display_freeze_alert(resp);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 3) {
            int64_t cents = read_money_cents("Enter withdrawal amount (₹): ");
            if (cents <= 0) {
                printf(COLOR_RED "Invalid amount. Must be positive.\n" COLOR_RESET);
                continue;
            }
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "WITHDRAW|%lld", (long long)cents);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else if (strstr(resp, "ACCOUNT_FROZEN")) {
                    display_freeze_alert(resp);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 4) {
            char rec_str[32];
            read_string("Enter Receiver Account ID: ", rec_str, sizeof(rec_str));
            int rec_id = atoi(rec_str);
            if (rec_id <= 0) {
                printf(COLOR_RED "Invalid account ID.\n" COLOR_RESET);
                continue;
            }
            int64_t cents = read_money_cents("Enter transfer amount (₹): ");
            if (cents <= 0) {
                printf(COLOR_RED "Invalid amount. Must be positive.\n" COLOR_RESET);
                continue;
            }
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "TRANSFER|%d|%lld", rec_id, (long long)cents);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else if (strstr(resp, "ACCOUNT_FROZEN")) {
                    display_freeze_alert(resp);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 5) {
            int64_t cents = read_money_cents("Enter loan amount requested (₹): ");
            if (cents <= 0) {
                printf(COLOR_RED "Invalid amount.\n" COLOR_RESET);
                continue;
            }
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "APPLY_LOAN|%lld", (long long)cents);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else if (strstr(resp, "ACCOUNT_FROZEN")) {
                    display_freeze_alert(resp);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 6) {
            if (send_command("VIEW_HISTORY", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 7) {
            char fb_msg[256];
            read_string("Enter your feedback/message: ", fb_msg, sizeof(fb_msg));
            if (strlen(fb_msg) == 0) continue;
            char cmd[300];
            snprintf(cmd, sizeof(cmd), "ADD_FEEDBACK|%s", fb_msg);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 8) {
            char new_pwd[64];
            read_string("Enter new password: ", new_pwd, sizeof(new_pwd));
            if (strlen(new_pwd) == 0) continue;
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s", new_pwd);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 9) {
            send_command("LOGOUT", resp, sizeof(resp));
            printf(COLOR_YELLOW "Logged out.\n" COLOR_RESET);
            break;
        } else {
            printf(COLOR_RED "Invalid selection.\n" COLOR_RESET);
        }
    }
}

static void handle_employee_menu(const char *username) {
    while (1) {
        printf("\n" COLOR_BLUE "=== BANK EMPLOYEE PORTAL [%s] ===" COLOR_RESET "\n", username);
        printf("1. Create New Customer (with initial balance)\n");
        printf("2. View Customer Passbook\n");
        printf("3. View Assigned Loan Applications\n");
        printf("4. Process Assigned Loan (Approve / Reject)\n");
        printf("5. Change Password\n");
        printf("6. Logout\n");

        char choice[16];
        read_string(COLOR_CYAN "Choose an option (1-6): " COLOR_RESET, choice, sizeof(choice));
        int c = atoi(choice);

        char resp[BUFFER_SIZE];
        if (c == 1) {
            char c_name[64], c_pass[64];
            read_string("Enter new customer username: ", c_name, sizeof(c_name));
            read_string("Enter initial password: ", c_pass, sizeof(c_pass));
            int64_t init_cents = read_money_cents("Enter initial balance (₹, e.g. 100): ");
            if (init_cents < 0) init_cents = 0;

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "ADD_CUSTOMER|%s|%s|%lld", c_name, c_pass, (long long)init_cents);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 2) {
            char uid_str[32];
            read_string("Enter Customer User ID: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "VIEW_PASSBOOK|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 3) {
            if (send_command("VIEW_ASSIGNED_LOANS", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 4) {
            char lid_str[32], dec_str[32];
            read_string("Enter Loan ID to process: ", lid_str, sizeof(lid_str));
            read_string("Enter Decision (APPROVED or REJECTED): ", dec_str, sizeof(dec_str));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "PROCESS_LOAN|%s|%s", lid_str, dec_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 5) {
            char new_pwd[64];
            read_string("Enter new password: ", new_pwd, sizeof(new_pwd));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s", new_pwd);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 6) {
            send_command("LOGOUT", resp, sizeof(resp));
            printf(COLOR_YELLOW "Logged out.\n" COLOR_RESET);
            break;
        } else {
            printf(COLOR_RED "Invalid selection.\n" COLOR_RESET);
        }
    }
}

static void handle_manager_menu(const char *username) {
    while (1) {
        printf("\n" COLOR_BLUE "=== BANK MANAGER CONSOLE [%s] ===" COLOR_RESET "\n", username);
        printf(COLOR_YELLOW "--- Anomaly & Freeze Controls ---" COLOR_RESET "\n");
        printf("1. View Open Anomaly Alerts\n");
        printf("2. View Frozen Accounts\n");
        printf("3. Inspect Alert Details\n");
        printf("4. Unfreeze & Resolve Anomaly Alert (Sender & Receiver)\n");
        printf(COLOR_YELLOW "--- Banking Operations ---" COLOR_RESET "\n");
        printf("5. View Pending Loan Applications\n");
        printf("6. Assign Loan to Employee\n");
        printf("7. Activate Customer Account\n");
        printf("8. Deactivate Customer Account\n");
        printf("9. Review Customer Feedback\n");
        printf("10. View Customer Passbook\n");
        printf("11. Change Password\n");
        printf("12. Logout\n");

        char choice[16];
        read_string(COLOR_CYAN "Choose an option (1-12): " COLOR_RESET, choice, sizeof(choice));
        int c = atoi(choice);

        char resp[BUFFER_SIZE];
        if (c == 1) {
            if (send_command("VIEW_ANOMALY_ALERTS", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 2) {
            if (send_command("VIEW_FROZEN_ACCOUNTS", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 3) {
            char aid_str[32];
            read_string("Enter Alert ID to inspect: ", aid_str, sizeof(aid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "VIEW_ANOMALY_DETAILS|%s", aid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 4) {
            char aid_str[32], note[256];
            read_string("Enter Alert ID to resolve & unfreeze: ", aid_str, sizeof(aid_str));
            read_string("Enter resolution note (e.g. Verified customer activity): ", note, sizeof(note));
            char cmd[350];
            snprintf(cmd, sizeof(cmd), "RESOLVE_ANOMALY|%s|%s", aid_str, note);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 5) {
            if (send_command("VIEW_PENDING_LOANS", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 6) {
            char lid_str[32], eid_str[32];
            read_string("Enter Loan ID: ", lid_str, sizeof(lid_str));
            read_string("Enter Employee User ID to assign to: ", eid_str, sizeof(eid_str));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "ASSIGN_LOAN|%s|%s", lid_str, eid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 7) {
            char uid_str[32];
            read_string("Enter Customer User ID to ACTIVATE: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "ACTIVATE_ACCOUNT|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 8) {
            char uid_str[32];
            read_string("Enter Customer User ID to DEACTIVATE: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "DEACTIVATE_ACCOUNT|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 9) {
            if (send_command("VIEW_FEEDBACK", resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 10) {
            char uid_str[32];
            read_string("Enter Customer User ID: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "VIEW_PASSBOOK|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 11) {
            char new_pwd[64];
            read_string("Enter new password: ", new_pwd, sizeof(new_pwd));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s", new_pwd);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 12) {
            send_command("LOGOUT", resp, sizeof(resp));
            printf(COLOR_YELLOW "Logged out.\n" COLOR_RESET);
            break;
        } else {
            printf(COLOR_RED "Invalid selection.\n" COLOR_RESET);
        }
    }
}

static void handle_admin_menu(const char *username) {
    while (1) {
        printf("\n" COLOR_BLUE "=== BANK ADMINISTRATOR SYSTEM [%s] ===" COLOR_RESET "\n", username);
        printf("1. Add New Bank Employee\n");
        printf("2. Manage User Role (Customer/Employee/Manager/Admin)\n");
        printf("3. Reset Any User Password\n");
        printf("4. Activate User Account\n");
        printf("5. Deactivate User Account\n");
        printf("6. View Customer Passbook\n");
        printf("7. Change Personal Password\n");
        printf("8. Logout\n");

        char choice[16];
        read_string(COLOR_CYAN "Choose an option (1-8): " COLOR_RESET, choice, sizeof(choice));
        int c = atoi(choice);

        char resp[BUFFER_SIZE];
        if (c == 1) {
            char emp_name[64], emp_pass[64];
            read_string("Enter new employee username: ", emp_name, sizeof(emp_name));
            read_string("Enter temporary password: ", emp_pass, sizeof(emp_pass));
            char cmd[150];
            snprintf(cmd, sizeof(cmd), "ADD_EMPLOYEE|%s|%s", emp_name, emp_pass);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 2) {
            char uid_str[32], role_str[32];
            read_string("Enter Target User ID: ", uid_str, sizeof(uid_str));
            read_string("Enter New Role (CUSTOMER / EMPLOYEE / MANAGER / ADMIN): ", role_str, sizeof(role_str));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "MANAGE_ROLE|%s|%s", uid_str, role_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 3) {
            char uid_str[32], pass_str[64];
            read_string("Enter Target User ID: ", uid_str, sizeof(uid_str));
            read_string("Enter New Password: ", pass_str, sizeof(pass_str));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "ADMIN_RESET_PASSWORD|%s|%s", uid_str, pass_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 4) {
            char uid_str[32];
            read_string("Enter User ID to ACTIVATE: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "ACTIVATE_ACCOUNT|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 5) {
            char uid_str[32];
            read_string("Enter User ID to DEACTIVATE: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "DEACTIVATE_ACCOUNT|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 6) {
            char uid_str[32];
            read_string("Enter Customer User ID: ", uid_str, sizeof(uid_str));
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "VIEW_PASSBOOK|%s", uid_str);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf("\n%s\n", resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 7) {
            char new_pwd[64];
            read_string("Enter new personal password: ", new_pwd, sizeof(new_pwd));
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s", new_pwd);
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 8) {
            send_command("LOGOUT", resp, sizeof(resp));
            printf(COLOR_YELLOW "Logged out.\n" COLOR_RESET);
            break;
        } else {
            printf(COLOR_RED "Invalid selection.\n" COLOR_RESET);
        }
    }
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        port = atoi(argv[1]);
    }

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sock < 0) {
        perror("Failed to create socket");
        return 1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        return 1;
    }

    if (connect(g_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf(COLOR_RED "Error: Could not connect to Bank Server on localhost:%d. Is the server running?\n" COLOR_RESET, port);
        return 1;
    }

    print_banner();

    while (1) {
        printf("\n" COLOR_CYAN "=== MAIN LOGIN MENU ===" COLOR_RESET "\n");
        printf("1. Customer Login\n");
        printf("2. Bank Employee Login\n");
        printf("3. Bank Manager Login\n");
        printf("4. Administrator Login\n");
        printf("5. Register New Customer Account\n");
        printf("6. Exit\n");

        char choice[16];
        read_string(COLOR_CYAN "Select option (1-6): " COLOR_RESET, choice, sizeof(choice));
        int c = atoi(choice);

        if (c >= 1 && c <= 4) {
            const char *role_str = (c == 1) ? ROLE_CUSTOMER_STR :
                                   (c == 2) ? ROLE_EMPLOYEE_STR :
                                   (c == 3) ? ROLE_MANAGER_STR  : ROLE_ADMIN_STR;

            char uname[64], pwd[64];
            printf("\n--- %s LOGIN ---\n", role_str);
            read_string("Enter Username: ", uname, sizeof(uname));
            read_string("Enter Password: ", pwd, sizeof(pwd));

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "LOGIN|%s|%s|%s", role_str, uname, pwd);

            char resp[BUFFER_SIZE];
            if (send_command(cmd, resp, sizeof(resp)) != 0) {
                break;
            }

            if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                // Check if account is frozen
                if (strstr(resp, "FROZEN")) {
                    display_freeze_alert("Repeated transaction anomaly detected. Contact manager for resolution.");
                } else {
                    printf(COLOR_GREEN "\n>>> Login successful!\n" COLOR_RESET);
                }

                if (c == 1) handle_customer_menu(uname);
                else if (c == 2) handle_employee_menu(uname);
                else if (c == 3) handle_manager_menu(uname);
                else if (c == 4) handle_admin_menu(uname);
            } else {
                if (strstr(resp, "ALREADY_LOGGED_IN")) {
                    printf(COLOR_RED "\n>>> [SECURITY ALERT]: This user already has an active session on another terminal!\n" COLOR_RESET);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 5) {
            char uname[64], pwd[64];
            printf("\n--- CUSTOMER REGISTRATION ---\n");
            read_string("Enter Desired Username: ", uname, sizeof(uname));
            read_string("Enter Password: ", pwd, sizeof(pwd));

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "REGISTER|%s|%s", uname, pwd);
            char resp[BUFFER_SIZE];
            if (send_command(cmd, resp, sizeof(resp)) == 0) {
                if (strncmp(resp, RESP_SUCCESS, 8) == 0) {
                    printf(COLOR_GREEN "\n>>> %s\n" COLOR_RESET, resp + 8);
                } else {
                    printf(COLOR_RED "\n>>> %s\n" COLOR_RESET, resp);
                }
            }
        } else if (c == 6) {
            printf(COLOR_YELLOW "Goodbye!\n" COLOR_RESET);
            break;
        } else {
            printf(COLOR_RED "Invalid selection.\n" COLOR_RESET);
        }
    }

    close(g_sock);
    return 0;
}
