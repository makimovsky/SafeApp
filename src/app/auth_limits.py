import time

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300
DELAY_TIME = 2

login_attempts = {}


def record_failed_attempt(client_ip):
    if client_ip not in login_attempts:
        login_attempts[client_ip] = {"count": 0, "last_attempt": time.time()}
    login_attempts[client_ip]["count"] += 1
    login_attempts[client_ip]["last_attempt"] = time.time()


def is_locked_out(client_ip):
    if client_ip not in login_attempts:
        return False

    attempts = login_attempts[client_ip]

    if attempts["count"] >= MAX_LOGIN_ATTEMPTS:
        if time.time() - attempts["last_attempt"] < LOCKOUT_TIME:
            return True
        else:
            reset_attempts(client_ip)
    return False


def reset_attempts(client_ip):
    if client_ip in login_attempts:
        del login_attempts[client_ip]
