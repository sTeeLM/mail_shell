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


class LoggerWriter:
    def __init__(self, prog_name, log_file,verbose):
        fmt_console = '[%(levelname)s] %(message)s'
        fmt_file  = '%(asctime)s|%(filename)s|%(lineno)d|%(levelname)s|%(process)s|%(message)s'
        log_level = logging.DEBUG
        if log_file != '':
            self.logger = logging.getLogger(prog_name)
            self.logger.setLevel(log_level)
            log_handle = logging.FileHandler(log_file, 'a', encoding='utf-8')
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
            self.logger.debug(msg.strip('\r\n'))

    def flush(self):
        pass

    def debug(self, msg):
        self.logger.debug(msg.strip('\r\n'))

    def warn(self, msg):
        self.logger.warn(msg.strip('\r\n'))

    def error(self, msg):
        self.logger.error(msg.strip('\r\n'))

    def info(self, msg):
        self.logger.info(msg.strip('\r\n'))

def init_log(
    prog_name,
    log_file,
    verbose=False
):
    fmt_console = '[%(levelname)s] %(message)s'
    fmt_file  = '%(asctime)s|%(filename)s|%(lineno)d|%(levelname)s|%(process)s|%(message)s'
    log_level = logging.DEBUG
    if log_file != '':
        logger = logging.getLogger(prog_name)
        logger.setLevel(log_level)
        log_handle = logging.FileHandler(log_file, 'a', encoding='utf-8')
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
    logger.write = lambda msg: logging.debug(msg.strip('\r\n')) if msg != '\n' else None
    logger.flush = empty_call
    return logger


def usage(prog_name, parsed_options):
    sys.stderr.write("%s:\n" % (prog_name))
    for (opt, value) in sorted(parsed_options.items(), key=lambda item: item[1][4]):
        sys.stderr.write(
            "   -%s|--%s : %s\n"
            % (parsed_options[opt][0].strip(':'), opt, parsed_options[opt][3]))

        if parsed_options[opt][1] != None:
            if parsed_options[opt][0][-1] == ':':
                sys.stderr.write('      optional, need argument, default: "%s"\n' % str(parsed_options[opt][1]))
            else:
                sys.stderr.write('      optional, default: "%s"\n' % str(parsed_options[opt][1]))
        else:
            if parsed_options[opt][0][-1] == ':':
                sys.stderr.write('      required, need argument\n')
            else:
                sys.stderr.write('      required\n')


def dump_options(parsed_options, logger):
    logger.debug('-------------dump options begin--------------')
    for (opt, value) in sorted(parsed_options.items(), key=lambda item: item[1][4]):
        logger.debug(
            "%s: default %s, current %s" % (opt, parsed_options[opt][1], parsed_options[opt][2])
        )
    logger.debug('-------------dump options end--------------')

def get_opt_by_name(parsed_options, opt):
    if parsed_options[opt][2]:
        return parsed_options[opt][2]
    else:
        return parsed_options[opt][1]

def parse_option(argv, parsed_options):
    short_opts = ''
    long_opts = []
    reverse_opt_hash = {}
    for key in parsed_options:
        short_opts += parsed_options[key][0]
        if parsed_options[key][0][-1] == ':':
            long_opts.append(key + '=')
        else:
            long_opts.append(key)
        reverse_opt_hash[('-' + parsed_options[key][0].strip(':'), '--' + key)] = key

    try:
        opts, arg = getopt.getopt(argv[1:], short_opts, long_opts)
        for opt, arg in opts:
            for (short_opt, long_opt) in reverse_opt_hash:
                if opt in (short_opt, long_opt):
                    if (parsed_options[reverse_opt_hash[(short_opt, long_opt)]][0][-1] == ':'):  
                        parsed_options[reverse_opt_hash[(short_opt, long_opt)]][2] = arg
                    else:
                        parsed_options[reverse_opt_hash[(short_opt, long_opt)]][2] = True
    except getopt.GetoptError as err:
        sys.stderr.write("command line parse error: %s\n" % (err))
        usage(argv[0], parsed_options)
        return False
    return True

def parse_overides(logger, subjects_str):
    overides = {}
    if subjects_str:
        opts = subjects_str.split(':')
    for opt in opts:
        if len(opt.split('=')) == 2:
            (key, val) = opt.split('=')
            overides[key] = val
    return overides

def fetch_cmd_pop(logger, cmd_timeout, cmd_server, 
    cmd_protocol, cmd_username, cmd_password, magic_word, is_ssl):
    comm = None
    overides = None
    with contextlib.redirect_stdout(logger):
        if not is_ssl:
            try:
                cmd_obj = poplib.POP3(
                    host = cmd_server,
                    timeout = cmd_timeout)
            except Exception as ext:
                logger.error('can not connect %s as %s: %s' % 
                    (cmd_server, cmd_protocol, str(ext)));
                return (None, None)
        else:
            try:
                cmd_obj = poplib.POP3_SSL(
                    host = cmd_server,
                    timeout = cmd_timeout)
            except Exception as ext:
                logger.error('can not connect %s as %s: %s' % 
                    (cmd_server, cmd_protocol, str(ext)));
                return (None, None)

        cmd_obj.set_debuglevel(2)
        logger.info('connect to %s as %s ok' % (
            cmd_server, cmd_protocol))

        try:
            state = cmd_obj.user(cmd_username)
            logger.info('login with user response %s' % (state));

            state = cmd_obj.pass_(cmd_password)
            logger.info('login with password response %s' % (state));

            resp, mails, octets = cmd_obj.list()
            logger.info('list return %s' % (resp));

            for i in range(len(mails)):
                resp, lines, octets = cmd_obj.retr(i+1)
                msg_content = b'\r\n'.join(lines).decode('utf-8')
                msg = email.parser.Parser().parsestr(msg_content)
                if msg.get_content_type() != 'text/plain':
                    logger.debug('skip non-text/plain payload \n%s' % (str(msg)))
                    continue
                if msg.get('Subject').find(magic_word) == 0:
                    comm = msg.get_payload(decode = True).decode('utf-8').rstrip('\r\n ').strip('\r\n ')
                    overides = parse_overides(logger, msg.get('Subject'))
                    logger.info('fetched command: "%s" %s' % (comm, overides))
                    state = cmd_obj.dele(i+1)
                    logger.info('dele return %s' % (resp));
                    break;  
            logger.info('quit fetch process')
            cmd_obj.quit()
            cmd_obj.close()
        except Exception as ext:
            cmd_obj.close()
            logger.error('can not fetch cmd: %s' % (str(ext)))
    return (comm, overides)


def fetch_cmd_imap(logger, cmd_timeout, cmd_server, 
    cmd_protocol, cmd_username, cmd_password, magic_word, is_ssl):
    comm = None
    overides = None
    with contextlib.redirect_stderr(logger):
        if not is_ssl:
            try:
                cmd_obj = imaplib.IMAP4(
                    host = cmd_server,
                    timeout = cmd_timeout)
            except Exception as ext:
                logger.error('can not connect %s as %s: %s' % 
                    (cmd_server, cmd_protocol, str(ext)));
                return (None, None)
        else:
            try:
                cmd_obj = imaplib.IMAP4_SSL(
                    host = cmd_server,
                    timeout = cmd_timeout)
            except Exception as ext:
                logger.error('can not connect %s as %s: %s' % 
                    (cmd_server, cmd_protocol, str(ext)));
                return (None, None)
     
        cmd_obj.debug = 10
        logger.info('connect to %s as %s ok' % (
            cmd_server, cmd_protocol))

        try:
            state, response = cmd_obj.login(cmd_username, cmd_password)
            logger.info('login into host %s %s %s' % (
                    cmd_server,
                    state, response))
                
            state, response = cmd_obj.select('INBOX')
            logger.info('switch into inbox response %s %s' % (
                    state, response))

            state, response = cmd_obj.search(None, 'ALL')
            logger.info('search return %s %s' % (state, response))

            for i in response[0].split():
                state, res = cmd_obj.fetch(i, '(RFC822)')
                msg = email.message_from_bytes(res[0][1])
                logger.debug('fetched message \n%s' % (str(msg)))
                if msg.get_content_type() != 'text/plain':
                    logger.warn('skip non-text/plain payload \n%s' % (str(msg)))
                    continue
                if msg.get('Subject').find(magic_word) == 0:
                    comm = msg.get_payload(decode = True).decode('utf-8').rstrip('\r\n ').strip('\r\n ')
                    overides = parse_overides(logger, msg.get('Subject'))
                    logger.info('fetched command: "%s" %s' % (comm, overides))
                    state, res = cmd_obj.store(i, '+FLAGS', '\\Deleted')
                    logger.info('delete mail number %s %s %s' % (
                        i, state, res))
                    break;
            logger.info('quit fetch process')
            cmd_obj.close()
            cmd_obj.logout()
        except Exception as ext:
            cmd_obj.logout()
            logger.error('can not fetch cmd: %s' % (str(ext)))
    return (comm,overides)    

def fetch_cmd(parsed_options, logger, identity):
    (cmd_server, cmd_protocol, cmd_username, cmd_password) \
        = (
            identity['command']['server'],
            identity['command']['protocol'],
            identity['command']['username'],
            identity['command']['password'],
        )
    
    if cmd_protocol == 'imap' or cmd_protocol == 'imap-ssl':
        return fetch_cmd_imap(
            logger,
            get_opt_by_name(parsed_options, 'read-timeout'),
            cmd_server, cmd_protocol, cmd_username, cmd_password,
            get_opt_by_name(parsed_options, 'magic-word'),
            cmd_protocol == 'imap-ssl'
        )
    elif cmd_protocol == 'pop' or cmd_protocol == 'pop-ssl':
        return fetch_cmd_pop(
            logger,
            get_opt_by_name(parsed_options, 'read-timeout'),
            cmd_server, cmd_protocol, cmd_username, cmd_password,
            get_opt_by_name(parsed_options, 'magic-word'),
            cmd_protocol == 'pop-ssl'
        )
    else:
        return (None, None)

def run_cmd(parsed_options, logger, comm, overides):
    res = None
    time_out = get_opt_by_name(parsed_options, 'run-timeout')
    no_res = get_opt_by_name(parsed_options, 'no-res')

    if overides and overides.get("timeout"):
        time_out = int(overides['timeout'])

    if time_out == 0:
        time_out = None

    if overides and overides.get("no-res"):
        no_res = overides['no-res'] == 'true'

    logger.debug('will run cmd "%s" %s' % (comm, overides))

    try:
        stdout_file = open('/tmp/stdout_file_mail_shell','w+')
        stderr_file = open('/tmp/stderr_file_mail_shell','w+')
        result = subprocess.run(
            comm, 
            shell=True, 
            stdout=stdout_file, 
            stderr=stderr_file, 
            timeout=time_out)
        stdout_file.seek(0)
        stderr_file.seek(0)
        res = 'run command ok:\nstdout:\n'
        res += stdout_file.read()
        res += 'stderr:\n'
        res += stderr_file.read()
        stdout_file.close()
        stderr_file.close()
    except Exception as ext:
        logger.error('can not run cmd "%s": %s' % (comm, str(ext)))
        res = 'run command failed: %s\n' %(str(ext))
    if not no_res:
        return res
    else:
        logger.info('no-res overide set, not response send');
        return None

def email_format_addr(s):
    name, addr = email.utils.parseaddr(s)
    return email.utils.formataddr((email.header.Header(name, 'utf-8').encode(), addr))

def send_res(parsed_options, logger, identity, comm, res):
    logger.debug('will send comm res "%s" "%s"' % (comm, res))
    (res_server, res_protocol, res_username, res_password) =  \
        (
            identity['response']['server'],
            identity['response']['protocol'],
            identity['response']['username'],
            identity['response']['password'],
        )
    (from_email, to_email) = (identity['email']['from'], identity['email']['to'])
    msg = email.mime.text.MIMEText(res, 'plain', 'utf-8')
    msg['From'] = email_format_addr('%s <%s>' % (from_email, from_email))
    msg['To'] = email_format_addr('%s <%s>' % (to_email, to_email))
    msg['Subject'] = email.header.Header(get_opt_by_name(parsed_options, 
        'res-subject') % (comm), 'utf-8').encode()
    with contextlib.redirect_stderr(logger):
        try:
            if res_protocol == 'smtp':
                res_obj = smtplib.SMTP(host = res_server,
                    timeout = get_opt_by_name(parsed_options, 'send-timeout'))
            elif res_protocol == 'smtp-ssl':
                res_obj = smtplib.SMTP_SSL(host = res_server,
                    timeout = get_opt_by_name(parsed_options, 'send-timeout'))
            else:
                res_obj = smtplib.SMTP(host = res_server,
                    timeout = get_opt_by_name(parsed_options, 'send-timeout'))
        except Exception as ext:
            logger.error('can not connect %s as %s: %s' % 
                (res_server, res_protocol, str(ext)));
            return

        try:
            res_obj.set_debuglevel(2)
            logger.info('connect to %s as %s ok' % (res_server, res_protocol))
            if res_protocol == 'smtp-starttls':
                code, response = res_obj.starttls()
                logger.info('start-tls response %s %s' %(code, response));

            code, response = res_obj.login(res_username, res_password)
            logger.info('login response %s %s' %(code, response));
            res_obj.sendmail(from_email, [to_email], msg.as_string())
            logger.info('send mail ok');
            res_obj.quit();
            res_obj.close()
        except Exception as ext:
            res_obj.close()
            logger.error('can not send response to %s as %s: %s' % 
                    (res_server, res_protocol, str(ext)));
    
def load_identity_file(parsed_options, logger):
    config = configparser.ConfigParser()
    indentity = {}
    try:
        config.read(get_opt_by_name(parsed_options, 'identity-file'))
        indentity['command'] = {
            'server' : config['command']['server'],
            'protocol' : config['command']['protocol'],
            'username' : config['command']['username'],
            'password' : config['command']['password'],
        }
        indentity['response'] = {
            'server' : config['response']['server'],
            'protocol' : config['response']['protocol'],
            'username' : config['response']['username'],
            'password' : config['response']['password'],
        }
        indentity['email'] = {
            'from' : config['email']['from'],
            'to' : config['email']['to'],
        }
    except Exception as ext:
        logger.error('can not read indenty-file %s' \
            % (get_opt_by_name(parsed_options, 'identity-file')))
        return None

    return indentity
 
def verify_option(parsed_options, logger):
    if not get_opt_by_name(parsed_options, 'identity-file') :
        logger.error('identity-file not set');
        return False

    identity = load_identity_file(parsed_options, logger)
    if not identity:
        logger.error('identity-file load failed');
        return False

    if not identity['command']['server'] or \
        not identity['command']['protocol'] or \
        not identity['command']['username'] or \
        not identity['command']['password']:
        logger.error('command server not set or invalid');
        return False

    if identity['command']['protocol'] != 'imap' and \
       identity['command']['protocol'] != 'imap-ssl' and \
       identity['command']['protocol'] != 'pop' and \
       identity['command']['protocol'] != 'pop-ssl':
        logger.error('invalid protocol %s' % (
            identity['command']['protocol']
        ));
        return False

    if not identity['response']['server'] or \
        not identity['response']['protocol'] or \
        not identity['response']['username'] or \
        not identity['response']['password']:
        logger.error('response server not set or invalid');
        return False

    if identity['response']['protocol'] != 'smtp' and \
       identity['response']['protocol'] != 'smtp-ssl' and \
       identity['response']['protocol'] != 'smtp-starttls' :
        logger.error('invalid res-protocol %s' % (
            identity['response']['protocol']
        ));
        return False
    return True


def main(argv):
    # log-opt-name, [short-opt, default, current, desc, order]
    parsed_options = {
        'identity-file' : ['f:', None, None, 'identity of command server and response server', 0],
        'magic-word' : ['m:', 'mail shell', None, 'magic word of subject', 1],
        'res-subject' : ['s:', 'Response of %s', None, 'patten of response subject', 2],
        'no-res' : ['n', False, None, 'do not send response', 3],
        'read-timeout' : ['r:', 10, None, 'read command at most x seconds', 4],
        'send-timeout' : ['w:', 10, None, 'write response at most x seconds', 5],
        'run-timeout' : ['t:', 10, None, 'run command at most x seconds', 6],
        'verbose': ['v', False, None, 'verbose log', 7],
        'log-file': ['l:', '', None, 'log to file, empty means log on screen', 8],
        'help': ['h', False, None, 'show help', 9],
    }

    if not parse_option(argv, parsed_options):
        return 1

    if get_opt_by_name(parsed_options, 'help'):
        usage(argv[0], parsed_options)
        return 0

    logger = LoggerWriter(argv[0], get_opt_by_name(parsed_options, 'log-file'), 
        get_opt_by_name(parsed_options, 'verbose'))

    if not verify_option(parsed_options, logger):
        usage(argv[0], parsed_options)
        return 1

    dump_options(parsed_options, logger)

    identity = load_identity_file(parsed_options, logger)

    (comm, overides) = fetch_cmd(parsed_options, logger, identity)

    if comm:
        res = run_cmd(parsed_options, logger, comm, overides)
        if res and not get_opt_by_name(parsed_options, 'no-res'):
            send_res(parsed_options, logger, identity, comm, res)

main(sys.argv)
