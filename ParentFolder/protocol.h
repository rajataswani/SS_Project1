#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Response prefixes */
#define RESP_SUCCESS "SUCCESS|"
#define RESP_ERROR   "ERROR|"

/* Error codes */
#define ERR_ALREADY_LOGGED_IN "ERROR|ALREADY_LOGGED_IN|This user already has an active session."
#define ERR_ACCOUNT_FROZEN    "ERROR|ACCOUNT_FROZEN|Your account is frozen due to repeated same-amount transaction activity. Contact a bank manager for resolution."
#define ERR_UNAUTHORIZED      "ERROR|UNAUTHORIZED|You do not have permission to perform this action."
#define ERR_NOT_LOGGED_IN     "ERROR|NOT_LOGGED_IN|Please log in first."
#define ERR_INVALID_ARGS      "ERROR|INVALID_ARGS|Invalid arguments provided."
#define ERR_NOT_FOUND         "ERROR|NOT_FOUND|Record not found."
#define ERR_INSUFFICIENT_FUNDS "ERROR|INSUFFICIENT_FUNDS|Insufficient funds for this operation."
#define ERR_ACCOUNT_DEACTIVATED "ERROR|ACCOUNT_DEACTIVATED|Account is deactivated. Contact bank."

#endif /* PROTOCOL_H */
