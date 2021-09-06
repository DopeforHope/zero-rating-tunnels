import threading
from multiprocessing import Queue
import sys
from urllib.parse import urlparse, parse_qs
import requests
import logging
from telegram.client import Telegram
import time
import uuid
import subprocess
import os

# CONFIGURATION VARIABLES
CLIENT_ID = 1241064075
SERVER_ID = 1178350582
DEBUG = True


# If ONEFILE is set to true the request executer will generate one html file out of the request.
# For this is https://github.com/zTrix/webpage2html used.
# The project doesn't support orther methods than GET and doesn't support custom headers/cookies right now.
# ATTENTION: You need a symlink to the webpage2html.py file into your executing directory or need that file in your
# directory.
ONEFILE = True
# The according python interpreter which is used to execute webpage2html
PYTHON_INTERPRETER = "/home/dopeforhope/virtualEnv/webpage2html/bin/python3"
# Shall Javascript enabled for webpage2html.py?
JAVASCRIPT = False

if ONEFILE:
    if not os.path.exists("webpage2html.py"):
        raise Exception("[Main] webpage2html.py not found")


def setup_logging(level=logging.INFO):
    root = logging.getLogger()
    root.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)


#--- Setup Phase ---#
setup_logging(level=logging.INFO)
print('[Main] Logger configured')
print('[Main] Login finished')



RECEIVER_ID = CLIENT_ID

tg = Telegram(
    api_id=1234567,
    api_hash='cafebabe',
    phone='+491521234567',
    database_encryption_key='dolphins',
    # TODO: Adjust the path to the libtdjson file
    library_path="./libtdjson.so.1.5.4",
    # TODO: Adjust to your preference
    use_secret_chats=True
)

tg.login()

print("[Main] Getting chats...")
result = tg.call_method("getChats", params={'offset_order': 2 ** 63 - 1,
                                            'offset_chat_id': 0, 'limit': 100})
result.wait()
if result.update is None:
    raise Exception("Result is None")
if DEBUG: print(result.update)

print("[Main] Setting online status...")

chat_id = "unknown"

# Set online status
data = {
    '@type': 'setOption',
    'name': 'online',
    'value': {
        '@type': 'optionValueBoolean',
        'value': True,
    },
}

tg._send_data(data)


# this function will be called
# for each received message
def message_handler(update):
    if update['message']['date'] < handler_start_time:
        if DEBUG: print('[Message Handler] Discarding old message')
    elif update['message']['is_outgoing']:
        if DEBUG: print("[Message Handler] Discarding own message")
    elif update['message']['sender_user_id'] != RECEIVER_ID:
        if DEBUG: print('[Message Handler] Discarding message from unknown sender')
    else:
        print('New message!')
        if DEBUG: print(update)

        # update chat ID if not known or new - the case when you receive the first msg of a new chat as a server
        current_chat_id = update['message']['chat_id']
        global chat_id
        if chat_id != current_chat_id:
            if chat_id == 'unknown':
                chat_id = current_chat_id
                wait_for_chat_id.set()
            else:
                chat_id = current_chat_id

        # check if its' normal text:
        if update['message']['content']['@type'] == 'messageText':
            text = update['message']['content']['text']['text']
            if DEBUG: print("[Message Handler] Received message with the following text: {}".format(text))
            message = text.split("\n")
            #check first line
            print("[Message Handler] Check if message is valid...")
            if message[0] != "HTTP_Tunnel" and message[0] != "HTTPS_Tunnel":
                print("[Message Handler] Discard malformed message")
            else:
                request_queue.put(message)


def request_executer():
    def return_error(content):
        answer_string = "HTTP/1.1 569 TUNNEL_ERROR\n" \
                        "Content-Type: text/html; charset=utf-8"

        if type(content) is str:
            content = content.encode('utf-8')

        path = "/tmp/error{}".format(time.time())
        with open(path, "wb") as f:
            f.write(content)

        answer_queue.put((answer_string, path))

    while True:
        # TODO: adjust for desired behaviour
        if DEBUG: print("[Request Executer] Sender waiting for queue input")
        message = request_queue.get()
        if DEBUG: print("[Request Executer] Preparing message for requests library")
        # take the HTTP query and prepare it for the requests library
        http_request_line = message[1].split(" ")
        method = http_request_line[0]

        if ONEFILE:
            # TODO: http vs. https
            if message[0] == "HTTP_Tunnel":
                url = http_request_line[1]
            elif message[0] == "HTTPS_Tunnel":
                url = http_request_line[1]
            else:
                print("[Request Executer] Tunnel type unknown! Returning Error")
                return_error("Tunnel Error\nTunnel type unknown")
                continue

            one_page_file_name = "/tmp/onepage{}".format(str(int(time.time())))

            if JAVASCRIPT:
                command = '{interpreter} webpage2html.py -s --errorpage "{site}" > {result_path}'.format(interpreter=PYTHON_INTERPRETER,
                                                                                    site=url,
                                                                                    result_path=one_page_file_name)
            else:
                command = '{interpreter} webpage2html.py --errorpage "{site}" > {result_path}'.format(interpreter=PYTHON_INTERPRETER,
                                                                                    site=url,
                                                                                    result_path=one_page_file_name)


            print("[Request Executer] Executing command:\n{}".format(command))
            print("[Request Executer] Time: {}".format(time.time()))

            webpage2html_process = subprocess.Popen(command, shell=True).wait()

            print("[Request Executer] Answer Time: {}".format(time.time()))

            if webpage2html_process != 0:
                return_error("Tunnel Error\nwebpage2html returned non-zero value")
                continue

            answer_string = "HTTP/1.1 200 OK\n" \
                            "Content-Type: text/html; charset=utf-8"
            filepath = one_page_file_name

        else:
            parsed_uri = urlparse(http_request_line[1])

            if message[0] == "HTTP_Tunnel":
                url = "http://" + parsed_uri.netloc + parsed_uri.path
            elif message[0] == "HTTPS_Tunnel":
                url = "https://" + parsed_uri.netloc + parsed_uri.path
            else:
                print("[Request Executer] Tunnel mode unknown! Discarding request")
                return_error("569 Tunnel Error\nTunnel type unknown")
                continue

            # can it be a problem that the value of the params dict is always a list? - nope requests regelt
            parameters = parse_qs(parsed_uri.query)
            # TODO: headers?

            print("[Request Executer] Executing Request")
            # execute the query
            response = requests.request(method, url, params=parameters)

            print("[Request Executer] Reconstructing HTTP answer")
            # reconstruct HTTP response line
            answer_string = "HTTP/{maj_version}.{min_version} {status_code} {status_message}\n".format(
                maj_version=response.raw.version // 10,
                min_version=response.raw.version % 10,
                status_code=response.status_code,
                status_message=response.reason
            )
            print("[Request Executer] Reconstructing HTTP answer headers")
            # add headers
            # print(response.headers)
            # TODO: this a workaround, because the chunked transportation doesnt apply for the client
            # TODO: research which header are important?
            for header_name in response.headers:
                if header_name == "Transfer-Encoding" or header_name == 'Content-Encoding':
                    continue
                answer_string += "{header_name}: {header_value}\n".format(
                    header_name=header_name,
                    header_value=response.headers[header_name]
                )

            # write the content to a file
            if DEBUG: print("[Request Executer] Response Content: {}".format(response.content))

            if DEBUG: print("[Request Executer] Writing response content to a file")

            filepath = "/tmp/{}".format(str(uuid.uuid4()))
            if DEBUG: print("[Request Executer] Filepath: {}".format(filepath))

            with open(filepath, mode="wb+") as f:
                f.write(response.content)

        answer_queue.put((answer_string, filepath))


def tdlib_sender():
    while True:
        # TODO: sending limit
        if DEBUG: print("[Sender] Sender waiting for queue input")
        anwer_string, filepath = answer_queue.get()
        send_data = {
            '@type': 'sendMessage',
            'chat_id': chat_id,
            'input_message_content': {
                '@type': 'inputMessageDocument',
                'document': {'@type': 'inputFileLocal', 'path': filepath},
                'caption': {'@type': 'formattedText', 'text': anwer_string}
            },
        }

        result = tg._send_data(send_data)
        result.wait()
        if DEBUG: print("[Sender] Sended result: ".format(result.update))
        if result is None:
            raise Exception("[Sender] Result of sended message was None")


request_queue = Queue()
answer_queue = Queue()

wait_for_chat_id = threading.Event()


# start the message handler
handler_start_time = time.time()
tg.add_message_handler(message_handler)


print('[Main] Waiting for chat...')
if not wait_for_chat_id.is_set():
    wait_for_chat_id.wait()
print('[Main] Chat established')

receive_worker = threading.Thread(target=request_executer)
receive_worker.setDaemon(True)
receive_worker.start()

receive_worker = threading.Thread(target=tdlib_sender)
receive_worker.setDaemon(True)
receive_worker.start()

while True:
    pass
