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

def init_log(
    prog_name,
    log_file,
    verbose=False
):
    fmt_console = '[%(levelname)s] %(message)s'
    fmt_file  = '%(asctime)s|%(filename)s|%(lineno)d|%(levelname)s|%(process)s|%(message)s'
    log_level = logging.DEBUG
    if log_file:
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
    return logger


def usage(prog_name, parsed_options):
    sys.stderr.write("%s:\n" % (prog_name))
    for (opt, value) in sorted(parsed_options.items(), key=lambda item: item[1][4]):
        sys.stderr.write(
            "   -%s|--%s: %s\n"
            % (parsed_options[opt][0].strip(':'), opt, parsed_options[opt][3])
        )
        if parsed_options[opt][0][-1] == ':':
            sys.stderr.write(
                "             arg reguired, default: %s\n" % str(parsed_options[opt][1])
            )
        else:
            sys.stderr.write("             default: %s\n" % str(parsed_options[opt][1]))

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

def fetch_cmd_pop(logger, cmd_timeout, cmd_server, 
    cmd_protocol, cmd_username, cmd_password, magic_word, is_ssl):
    comm = None

    if not is_ssl:
        try:
            cmd_obj = poplib.POP3(
                host = cmd_server,
                timeout = cmd_timeout
            )
        except Exception as ext:
            logger.error('can not connect %s as %s: %s' % 
                (cmd_server, cmd_protocol, str(ext)));
            return None
    else:
        try:
            cmd_obj = poplib.POP3_SSL(
                host = cmd_server,
                timeout = cmd_timeout
            )
        except Exception as ext:
            logger.error('can not connect %s as %s: %s' % 
                (cmd_server, cmd_protocol, str(ext)));
            return None

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
                logger.warn('skip non-text/plain payload \n%s' % (str(msg)))
                continue
            if msg.get('Subject').find(magic_word) != -1:
                comm = msg.get_payload(decode = True).decode('utf-8').rstrip('\r\n ').strip('\r\n ')
                state = cmd_obj.dele(i+1)
                logger.info('dele return %s' % (resp));
                continue;
        cmd_obj.quit()
        cmd_obj.close()
    except Exception as ext:
        logger.error('can not fetch cmd %s' % (str(ext)))
    return comm


def fetch_cmd_imap(logger, cmd_timeout, cmd_server, 
    cmd_protocol, cmd_username, cmd_password, magic_word, is_ssl):
    comm = None
    if not is_ssl:
        try:
            cmd_obj = imaplib.IMAP4(
                host = cmd_server,
                timeout = cmd_timeout
            )
        except Exception as ext:
            logger.error('can not connect %s as %s: %s' % 
                (cmd_server, cmd_protocol, str(ext)));
            return None
    else:
        try:
            cmd_obj = imaplib.IMAP4_SSL(
                host = cmd_server,
                timeout = cmd_timeout
            )
        except Exception as ext:
            logger.error('can not connect %s as %s: %s' % 
                (cmd_server, cmd_protocol, str(ext)));
            return None
 
    logger.info('connect to %s as %s ok' % (
        cmd_server, cmd_protocol))

    try:
        state, msg = cmd_obj.login(cmd_username, cmd_password)
        if state != 'OK' :
            logger.error('can not login into host %s %s %s' % (
                cmd_server,
                state, msg
            ))
            cmd_obj.close()
            return None
        else:
            logger.info('login into host %s %s %s' % (
                cmd_server,
                state, msg
            ))
            
        state, msg = cmd_obj.select('INBOX')
        if state != 'OK' :
            logger.error('can not switch into inbox %s %s' % (
                state, msg
            ))
            cmd_obj.close()
            return None
        else:
            logger.info('switch into inbox response %s %s' % (
                state, msg
            ))

        state, msg = cmd_obj.search(None, 'SUBJECT', magic_word)
        if state != 'OK' :
            logger.error('can not search magic word "%s" %s %s' % (
                magic_word,
                state, msg
            ))
            cmd_obj.close()
            return None
        else:
            logger.info('search magic word "%s" %s %s' % (
                magic_word,
                state, msg
            ))
        if len(msg) == 0 or not msg[0]:
            logger.info('no magic word found');
            cmd_obj.close()
            return None
        
        num_to_delete = msg[0]
        state, msg = cmd_obj.fetch(msg[0], '(RFC822)')
        if state != 'OK' or len(msg) == 0 or not msg[0]:
            logger.error('can fetch email %s %s' % (
                state, msg
            ))
            cmd_obj.close()
            return None
        comm = email.message_from_bytes(msg[0][1])
        logger.debug('fetched message \n%s' % (str(comm)))
        if comm.get_content_type() != 'text/plain':
            logger.warn('skip non-text/plain payload \n%s' % (str(comm)))
            cmd_obj.close()
            return None
        comm = comm.get_payload(decode = True).decode('utf-8').rstrip('\r\n ').strip('\r\n ')
        logger.info('fetched command: "%s"' % (comm))
        
        state, msg = cmd_obj.store(num_to_delete, '+FLAGS', '\\Deleted')
        if state != 'OK' :
            logger.error('can not delete mail number %s %s %s' % (
                num_to_delete,
                state, msg
            ))
            cmd_obj.close()
            return None
        else:
            logger.info('delete mail number %s %s %s' % (
                num_to_delete,
                state, msg
            ))
            cmd_obj.quit()
            cmd_obj.close()

    except Exception as ext:
        logger.error('can not fetch cmd %s' % (str(ext)))
    return comm    

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
        return None

def run_cmd(parsed_options, logger, comm):
    res = None
    logger.debug('will run cmd "%s"' % (comm))
    try:
        result = subprocess.run(
            comm, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=get_opt_by_name(parsed_options, 'run-timeout'))
        res = 'run command ok:\nstdout:\n'
        res += result.stdout.decode('utf-8')
        res += 'stderr:\n'
        res += result.stderr.decode('utf-8')
    except Exception as ext:
        logger.error('can not run cmd "%s": %s' % (comm, str(ext)))
        res = 'run command failed:\n'
        res += str(ext)
    return res

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
    msg['Subject'] = email.header.Header('Response for "%s"' % (comm), 'utf-8').encode()
    try:
        if res_protocol == 'smtp':
            res_obj = smtplib.SMTP(host = res_server,
                timeout = get_opt_by_name(parsed_options, 'send-timeout'))
            logger.info('connect to %s as %s ok' % (res_server, res_protocol))
        elif res_protocol == 'smtp-ssl':
            res_obj = smtplib.SMTP_SSL(host = res_server,
                timeout = get_opt_by_name(parsed_options, 'send-timeout'))
            logger.info('connect to %s as %s ok' % (res_server, res_protocol))
        else:
            res_obj = smtplib.SMTP(host = res_server,
                timeout = get_opt_by_name(parsed_options, 'send-timeout'))
            logger.info('connect to %s as %s ok' % (res_server, res_protocol))
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
        return None
    
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
        'no-res' : ['n', False, None, 'do not send response', 2],
        'read-timeout' : ['R:', 10, None, 'read command at most x seconds', 3],
        'send-timeout' : ['w:', 10, None, 'write response at most x seconds', 4],
        'run-timeout' : ['t:', 10, None, 'run command at most x seconds', 5],
        'verbose': ['v', False, None, 'verbose log', 6],
        'log-file': ['l:', None, None, 'log to file, not on screen', 7],
        'help': ['h', False, None, 'show help', 8],
    }

    if not parse_option(argv, parsed_options):
        return 1

    if get_opt_by_name(parsed_options, 'help'):
        usage(argv[0], parsed_options)
        return 0

    logger = init_log(argv[0], get_opt_by_name(parsed_options, 'log-file'), 
        get_opt_by_name(parsed_options, 'verbose'))

    if not verify_option(parsed_options, logger):
        usage(argv[0], parsed_options)
        return 1

    dump_options(parsed_options, logger)

    identity = load_identity_file(parsed_options, logger)

    comm = fetch_cmd(parsed_options, logger, identity)

    if comm:
        res = run_cmd(parsed_options, logger, comm)
        if res and not get_opt_by_name(parsed_options, 'no-res'):
            send_res(parsed_options, logger, identity, comm, res)

main(sys.argv)
