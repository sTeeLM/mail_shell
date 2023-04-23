#!/usr/bin/env python3
import imaplib
import poplib
import email
import email.parser
import email.mime.text
import email.header
import email.utils
import getopt
import sys
import logging
import subprocess
import smtplib
import configparser
import contextlib
import argparse


class LoggerWriter:
    def __init__(self, prog_name, log_file, verbose):
        fmt_console = "[%(levelname)s] %(message)s"
        fmt_file = (
            "%(asctime)s|%(filename)s|%(lineno)d|%(levelname)s|%(process)s|%(message)s"
        )
        log_level = logging.DEBUG
        if log_file != "":
            self.logger = logging.getLogger(prog_name)
            self.logger.setLevel(log_level)
            log_handle = logging.FileHandler(log_file, "a", encoding="utf-8")
            log_handle.setLevel(logging.DEBUG)
            log_formatter = logging.Formatter(fmt_file)
            log_handle.setFormatter(log_formatter)
            log_filter = logging.Filter()
            if verbose:
                log_filter.filter = lambda record: record.levelno >= logging.DEBUG
            else:
                log_filter.filter = lambda record: record.levelno >= logging.INFO
            log_handle.addFilter(log_filter)
            self.logger.addHandler(log_handle)
        else:
            if verbose:
                log_level = logging.DEBUG
            else:
                log_level = logging.INFO
            logging.basicConfig(format=fmt_console, level=log_level)
            self.logger = logging.getLogger(prog_name)

    def write(self, msg):
        if msg:
            self.logger.debug(msg.strip("\r\n"))

    def flush(self):
        pass

    def debug(self, msg):
        self.logger.debug(msg.strip("\r\n"))

    def warn(self, msg):
        self.logger.warn(msg.strip("\r\n"))

    def error(self, msg):
        self.logger.error(msg.strip("\r\n"))

    def info(self, msg):
        self.logger.info(msg.strip("\r\n"))


def init_log(prog_name, log_file, verbose=False):
    fmt_console = "[%(levelname)s] %(message)s"
    fmt_file = (
        "%(asctime)s|%(filename)s|%(lineno)d|%(levelname)s|%(process)s|%(message)s"
    )
    log_level = logging.DEBUG
    if log_file != "":
        logger = logging.getLogger(prog_name)
        logger.setLevel(log_level)
        log_handle = logging.FileHandler(log_file, "a", encoding="utf-8")
        log_handle.setLevel(logging.DEBUG)
        log_formatter = logging.Formatter(fmt_file)
        log_handle.setFormatter(log_formatter)
        log_filter = logging.Filter()
        if verbose:
            log_filter.filter = lambda record: record.levelno >= logging.DEBUG
        else:
            log_filter.filter = lambda record: record.levelno >= logging.INFO
        log_handle.addFilter(log_filter)
        logger.addHandler(log_handle)
    else:
        if verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        logging.basicConfig(format=fmt_console, level=log_level)
        logger = logging.getLogger(prog_name)
    logger.write = lambda msg: logging.debug(msg.strip("\r\n")) if msg != "\n" else None
    logger.flush = empty_call
    return logger



def dump_options(parsed_options, logger):
    logger.debug(str(parsed_options))


def get_opt_by_name(parsed_options, opt):
    return parsed_options[opt]


def parse_overides(logger, subjects_str):
    overides = {}
    if subjects_str:
        opts = subjects_str.split(":")
    for opt in opts:
        if len(opt.split("=")) == 2:
            (key, val) = opt.split("=")
            overides[key] = val
    return overides


def fetch_cmd_pop(
    logger,
    cmd_timeout,
    cmd_server,
    cmd_protocol,
    cmd_username,
    cmd_password,
    magic_word,
    is_ssl,
):
    comm = None
    overides = None
    with contextlib.redirect_stdout(logger):
        try:
            cmd_obj = (
                poplib.POP3_SSL(host=cmd_server, timeout=cmd_timeout)
                if is_ssl
                else poplib.POP3(host=cmd_server, timeout=cmd_timeout)
            )

        except Exception as ext:
            logger.error(
                "can not connect %s as %s: %s" % (cmd_server, cmd_protocol, str(ext))
            )
            return (None, None)

        cmd_obj.set_debuglevel(2)
        logger.info("connect to %s as %s ok" % (cmd_server, cmd_protocol))

        try:
            state = cmd_obj.user(cmd_username)
            logger.info("login with user response %s" % (state))

            state = cmd_obj.pass_(cmd_password)
            logger.info("login with password response %s" % (state))

            resp, mails, octets = cmd_obj.list()
            logger.info("list return %s" % (resp))

            for i in range(len(mails)):
                resp, lines, octets = cmd_obj.retr(i + 1)
                msg_content = b"\r\n".join(lines).decode("utf-8")
                msg = email.parser.Parser().parsestr(msg_content)
                if msg.get_content_type() != "text/plain":
                    logger.debug("skip non-text/plain payload \n%s" % (str(msg)))
                    continue
                if msg.get("Subject").find(magic_word) == 0:
                    comm = (
                        msg.get_payload(decode=True)
                        .decode("utf-8")
                        .rstrip("\r\n ")
                        .strip("\r\n ")
                    )
                    overides = parse_overides(logger, msg.get("Subject"))
                    logger.info('fetched command: "%s" %s' % (comm, overides))
                    state = cmd_obj.dele(i + 1)
                    logger.info("dele return %s" % (resp))
                    break
            logger.info("quit fetch process")
            cmd_obj.quit()
            cmd_obj.close()
        except Exception as ext:
            cmd_obj.close()
            logger.error("can not fetch cmd: %s" % (str(ext)))
    return (comm, overides)


def fetch_cmd_imap(
    logger,
    cmd_timeout,
    cmd_server,
    cmd_protocol,
    cmd_username,
    cmd_password,
    magic_word,
    is_ssl,
):
    comm = None
    overides = None
    with contextlib.redirect_stderr(logger):
        try:
            cmd_obj = (
                poplib.IMAP4_SSL(host=cmd_server, timeout=cmd_timeout)
                if is_ssl
                else poplib.IMAP4(host=cmd_server, timeout=cmd_timeout)
            )
        except Exception as ext:
            logger.error(
                "can not connect %s as %s: %s" % (cmd_server, cmd_protocol, str(ext))
            )
            return (None, None)

        cmd_obj.debug = 10
        logger.info("connect to %s as %s ok" % (cmd_server, cmd_protocol))

        try:
            state, response = cmd_obj.login(cmd_username, cmd_password)
            logger.info("login into host %s %s %s" % (cmd_server, state, response))

            state, response = cmd_obj.select("INBOX")
            logger.info("switch into inbox response %s %s" % (state, response))

            state, response = cmd_obj.search(None, "ALL")
            logger.info("search return %s %s" % (state, response))

            for i in response[0].split():
                state, res = cmd_obj.fetch(i, "(RFC822)")
                msg = email.message_from_bytes(res[0][1])
                logger.debug("fetched message \n%s" % (str(msg)))
                if msg.get_content_type() != "text/plain":
                    logger.warn("skip non-text/plain payload \n%s" % (str(msg)))
                    continue
                if msg.get("Subject").find(magic_word) == 0:
                    comm = (
                        msg.get_payload(decode=True)
                        .decode("utf-8")
                        .rstrip("\r\n ")
                        .strip("\r\n ")
                    )
                    overides = parse_overides(logger, msg.get("Subject"))
                    logger.info('fetched command: "%s" %s' % (comm, overides))
                    state, res = cmd_obj.store(i, "+FLAGS", "\\Deleted")
                    logger.info("delete mail number %s %s %s" % (i, state, res))
                    break
            logger.info("quit fetch process")
            cmd_obj.close()
            cmd_obj.logout()
        except Exception as ext:
            cmd_obj.logout()
            logger.error("can not fetch cmd: %s" % (str(ext)))
    return (comm, overides)


def fetch_cmd(parsed_options, logger, identity):
    (cmd_server, cmd_protocol, cmd_username, cmd_password) = (
        identity["command"]["server"],
        identity["command"]["protocol"],
        identity["command"]["username"],
        identity["command"]["password"],
    )

    if cmd_protocol == "imap" or cmd_protocol == "imap-ssl":
        return fetch_cmd_imap(
            logger,
            get_opt_by_name(parsed_options, "read_timeout"),
            cmd_server,
            cmd_protocol,
            cmd_username,
            cmd_password,
            get_opt_by_name(parsed_options, "magic_word"),
            cmd_protocol == "imap-ssl",
        )
    elif cmd_protocol == "pop" or cmd_protocol == "pop-ssl":
        return fetch_cmd_pop(
            logger,
            get_opt_by_name(parsed_options, "read_timeout"),
            cmd_server,
            cmd_protocol,
            cmd_username,
            cmd_password,
            get_opt_by_name(parsed_options, "magic_word"),
            cmd_protocol == "pop-ssl",
        )
    else:
        return (None, None)


def run_cmd(parsed_options, logger, comm, overides):
    res = None
    time_out = get_opt_by_name(parsed_options, "run_timeout")
    no_res = get_opt_by_name(parsed_options, "no_res")

    if overides and overides.get("timeout"):
        time_out = int(overides["timeout"])

    if time_out == 0:
        time_out = None

    if overides and overides.get("no-res"):
        no_res = overides["no-res"] == "true"

    logger.debug('will run cmd "%s" %s' % (comm, overides))

    try:
        stdout_file = open("/tmp/stdout_file_mail_shell", "w+")
        stderr_file = open("/tmp/stderr_file_mail_shell", "w+")
        result = subprocess.run(
            comm, shell=True, stdout=stdout_file, stderr=stderr_file, timeout=time_out
        )
        stdout_file.seek(0)
        stderr_file.seek(0)
        res = "run command ok:\nstdout:\n"
        res += stdout_file.read()
        res += "stderr:\n"
        res += stderr_file.read()
        stdout_file.close()
        stderr_file.close()
    except Exception as ext:
        logger.error('can not run cmd "%s": %s' % (comm, str(ext)))
        res = "run command failed: %s\n" % (str(ext))
    if not no_res:
        return res
    else:
        logger.info("no-res overide set, not response send")
        return None


def email_format_addr(s):
    name, addr = email.utils.parseaddr(s)
    return email.utils.formataddr((email.header.Header(name, "utf-8").encode(), addr))


def send_res(parsed_options, logger, identity, comm, res):
    logger.debug('will send comm res "%s" "%s"' % (comm, res))
    (res_server, res_protocol, res_username, res_password) = (
        identity["response"]["server"],
        identity["response"]["protocol"],
        identity["response"]["username"],
        identity["response"]["password"],
    )
    (from_email, to_email) = (identity["email"]["from"], identity["email"]["to"])
    msg = email.mime.text.MIMEText(res, "plain", "utf-8")
    msg["From"] = email_format_addr("%s <%s>" % (from_email, from_email))
    msg["To"] = email_format_addr("%s <%s>" % (to_email, to_email))
    msg["Subject"] = email.header.Header(
        get_opt_by_name(parsed_options, "res_subject") % (comm), "utf-8"
    ).encode()
    with contextlib.redirect_stderr(logger):
        try:
            if res_protocol == "smtp":
                res_obj = smtplib.SMTP(
                    host=res_server,
                    timeout=get_opt_by_name(parsed_options, "send_timeout"),
                )
            elif res_protocol == "smtp-ssl":
                res_obj = smtplib.SMTP_SSL(
                    host=res_server,
                    timeout=get_opt_by_name(parsed_options, "send_timeout"),
                )
            else:
                res_obj = smtplib.SMTP(
                    host=res_server,
                    timeout=get_opt_by_name(parsed_options, "send_timeout"),
                )
        except Exception as ext:
            logger.error(
                "can not connect %s as %s: %s" % (res_server, res_protocol, str(ext))
            )
            return

        try:
            res_obj.set_debuglevel(2)
            logger.info("connect to %s as %s ok" % (res_server, res_protocol))
            if res_protocol == "smtp-starttls":
                code, response = res_obj.starttls()
                logger.info("start-tls response %s %s" % (code, response))

            code, response = res_obj.login(res_username, res_password)
            logger.info("login response %s %s" % (code, response))
            res_obj.sendmail(from_email, [to_email], msg.as_string())
            logger.info("send mail ok")
            res_obj.quit()
            res_obj.close()
        except Exception as ext:
            res_obj.close()
            logger.error(
                "can not send response to %s as %s: %s"
                % (res_server, res_protocol, str(ext))
            )


def load_identity_file(parsed_options, logger):
    config = configparser.ConfigParser()
    indentity = {}
    try:
        config.read(get_opt_by_name(parsed_options, "identity_file"))
        indentity["command"] = {
            "server": config["command"]["server"],
            "protocol": config["command"]["protocol"],
            "username": config["command"]["username"],
            "password": config["command"]["password"],
        }
        indentity["response"] = {
            "server": config["response"]["server"],
            "protocol": config["response"]["protocol"],
            "username": config["response"]["username"],
            "password": config["response"]["password"],
        }
        indentity["email"] = {
            "from": config["email"]["from"],
            "to": config["email"]["to"],
        }
    except Exception as ext:
        logger.error(
            "can not read indenty-file %s"
            % (get_opt_by_name(parsed_options, "identity_file"))
        )
        return None

    return indentity


def verify_option(parsed_options, logger):
    if not get_opt_by_name(parsed_options, "identity_file"):
        logger.error("identity-file not set")
        return False

    identity = load_identity_file(parsed_options, logger)
    if not identity:
        logger.error("identity-file load failed")
        return False

    if (
        not identity["command"]["server"]
        or not identity["command"]["protocol"]
        or not identity["command"]["username"]
        or not identity["command"]["password"]
    ):
        logger.error("command server not set or invalid")
        return False

    if (
        identity["command"]["protocol"] != "imap"
        and identity["command"]["protocol"] != "imap-ssl"
        and identity["command"]["protocol"] != "pop"
        and identity["command"]["protocol"] != "pop-ssl"
    ):
        logger.error("invalid protocol %s" % (identity["command"]["protocol"]))
        return False

    if (
        not identity["response"]["server"]
        or not identity["response"]["protocol"]
        or not identity["response"]["username"]
        or not identity["response"]["password"]
    ):
        logger.error("response server not set or invalid")
        return False

    if (
        identity["response"]["protocol"] != "smtp"
        and identity["response"]["protocol"] != "smtp-ssl"
        and identity["response"]["protocol"] != "smtp-starttls"
    ):
        logger.error("invalid res-protocol %s" % (identity["response"]["protocol"]))
        return False
    return True


def main(argv):
    parser = argparse.ArgumentParser(
        prog='mail_shell',
        description='run shell command from message on email server and send response back to email server',
        epilog='by sTeeLM <steelm@madcat.cc> version 1.0.0',
        exit_on_error=True)

    parser.add_argument('-f', '--identity-file',
        action = 'store', 
        help = 'identity of command server and response server',
        required = True)
    parser.add_argument('-m', '--magic-word',
        action = 'store', 
        help = 'magic word of subject, default "%(default)s"',
        required = False,
        default = 'mail shell')
    parser.add_argument('-s', '--res-subject',
        action = 'store', 
        help = 'patten of response subject, default "%(default)s"',
        required = False,
        default = 'Response of "%s"')
    parser.add_argument('-n', '--no-res',
        action = 'store_true', 
        help = 'do not send response',
        required = False,
        default = False)
    parser.add_argument('-r', '--read-timeout',
        action = 'store', 
        help = 'read command at most x seconds, default %(default)ss',
        required = False,
        default = 30,
        type=int)
    parser.add_argument('-w', '--send-timeout',
        action = 'store', 
        help = 'write response at most x seconds, default %(default)ss',
        required = False,
        default = 30,
        type=int)
    parser.add_argument('-t', '--run-timeout',
        action = 'store', 
        help = 'run command at most x seconds, default %(default)ss',
        required = False,
        default = 30,
        type=int)
    parser.add_argument('-v', '--verbose',
        action = 'store_true', 
        help = 'verbose log',
        required = False,
        default = False)
    parser.add_argument('-l', '--log-file',
        action = 'store', 
        help = 'log to file, empty means log on screen',
        required = False,
        default = '')

    parsed_options = vars(parser.parse_args(sys.argv[1:]))

    logger = LoggerWriter(
        argv[0],
        get_opt_by_name(parsed_options, "log_file"),
        get_opt_by_name(parsed_options, "verbose"),
    )

    if not verify_option(parsed_options, logger):
        usage(argv[0], parsed_options)
        return 1

    dump_options(parsed_options, logger)

    identity = load_identity_file(parsed_options, logger)

    (comm, overides) = fetch_cmd(parsed_options, logger, identity)

    if comm:
        res = run_cmd(parsed_options, logger, comm, overides)
        if res and not get_opt_by_name(parsed_options, "no_res"):
            send_res(parsed_options, logger, identity, comm, res)
    return 0

sys.exit(main(sys.argv))
