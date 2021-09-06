# Partly copied from https://github.com/PiMaker/Teletun

from flask import Flask
from flask import request
from flask import Response
from telegram.client import Telegram
import sys
from multiprocessing import Queue, Lock
import threading
import time

#from OpenSSL import SSL
#context = SSL.Context(SSL.TLSv1_2_METHOD)
#context.use_privatekey_file('server.key')
#context.use_certificate_file('server.crt')

### pytg logging
import logging

# CONFIGURATION VARIABLES
SECRET_CHAT = False
CLIENT_ID = 1241064075
SERVER_ID = 1178350582
DEBUG = True


# Setup logging
def setup_logging(level=logging.INFO):
    root = logging.getLogger()
    root.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)


# --- Setup Phase ---#
setup_logging(level=logging.INFO)
print('[Main] Logger configured')

# let static files serve from the web and set local static files into nothing
app = Flask('__main__', static_url_path='/ofefqewrwqethewqoihfroiwqhronbwqonbfonhqonbfc')

sender_queue = Queue()
receiver_queue = Queue()
proxy_lock = Lock()


#TODO: payload
def build_text_request(method, url, http_version, request_headers, use_https=False):
    if use_https:
        text_request = "HTTPS_Tunnel\n"
    else:
        text_request = "HTTP_Tunnel\n"

    text_request += "{method} {url} {http_version}\n".format(
        method=method,
        url=url,
        http_version=http_version
    )
    print(request_headers)
    for header_name, header_value in request_headers:
        if use_https:
            if header_name == "Ssl-Terminated" or header_name == "Oldhost":
                continue
            #restore old host
            if header_name == "Host":
                header_value = request_headers['Oldhost']
        text_request += "{header_name}: {header_value}\n".format(
            header_name=header_name,
            header_value=header_value
        )

    return text_request


def send_and_get_answer(message):
    print("[Send and get answer] Putting message into queue")
    sender_queue.put(message)

    ### Document Version
    answer_tuple = receiver_queue.get()
    if answer_tuple[0] == "meta":
        meta = answer_tuple[1]
        document_tuple = receiver_queue.get()
        if document_tuple[0] == "document_file_path":
            downloaded_filepath = document_tuple[1]
        else:
            # TODO: right handling
            return None, None

    # elif answer_tuple[0] == "content":
    #    #TODO: handle desynchonization
    #    content = answer_tuple[1]
    else:
        return None, None
    print("[Send and get answer] Returning:\nMeta:\n{}\nFilepath:\n{}".format(meta, downloaded_filepath))
    return meta, downloaded_filepath



    # TODO: receive
    # TODO always
    # TODO: error handling


"""
GET Request
Input to tg: If we receive the GET Request we want to post the whole request as text message.
Therefore we print in the first line the normal Request Line and afterwards the simply the Header. Pretty straight forward
"""
@app.route('/', defaults={'foo': ''})
@app.route('/<path:foo>', methods=['GET', 'PUT', 'POST', 'DELETE', 'CONNECT'])
def proxy(foo):
    if request.method == 'CONNECT':
        return Response("Success")

    print("[Proxy] Incoming Request\n{}".format(request))
    if 'Ssl-Terminated' in request.headers and request.headers['Ssl-Terminated'] == 'True':
        use_https = True

        #rebuild url
        url = request.url.replace("127.0.0.1", request.headers['Oldhost'])

    else:
        use_https = False
        url = request.url

    tg_request = build_text_request(request.method, url,
                                    request.environ.get('SERVER_PROTOCOL'),
                                    request.headers, use_https=use_https)
    print("[Proxy] TG Request:\n{}".format(tg_request))

    if request.method == 'GET':

        print("[Proxy] Waiting for lock")
        proxy_lock.acquire()
        ### Document Version
        answer, downloaded_file_path = send_and_get_answer(tg_request)
        proxy_lock.release()
        if answer is None:
            return Response("Error", status=500)

        print("[Proxy] Opening Downloaded File...")
        #open downloaded file
        with open(downloaded_file_path, mode="rb") as f:
            answer_content = f.read()

        print("[Proxy] Content of downloaded file:\n{}".format(answer_content))

        resp = Response(answer_content, status=answer['status_code'])
        # set headers
        # print(answer['header'])
        # TODO: blacklist header workaround
        for header_field in answer['header']:
            resp.headers[header_field] = answer['header'][header_field]
        return resp

    elif request.method == 'PUT':
        pass
    elif request.method == 'POST':
        pass
    elif request.method == 'DELETE':
        pass

    #return get(f'{SITE_NAME}{path}').content
    return "Success"


if __name__ == '__main__':

    RECEIVER_ID = SERVER_ID
    ### TODO: insert your API credentials here and change the DB encryption key
    tg = Telegram(
        api_id=1234567,
        api_hash='cafebabe',
        phone='+491567891011',
        database_encryption_key='ChangeMe',
        # TODO: Adjust the path to the libtdjson file
        library_path="./libtdjson.so.1.5.4",
        # TODO: Adjust to your preference
        use_secret_chats=True
    )

    tg.login()

    print("[Main] Login Finished")


    print("[Main] Getting chats...")
    result = tg.call_method("getChats", params={'offset_order': 2 ** 63 - 1,
                                                'offset_chat_id': 0, 'limit': 100})
    result.wait()
    if result.update is None:
        raise Exception("[Main] Result is None")
    if DEBUG: print(result.update)

    if SECRET_CHAT:
        print("[Main] Trying to establish secret chat...")

        waiting_for_secret_chat = threading.Event()
        waiting_for_secret_chat_id = threading.Event()

        # this function will be called for every secret chat message
        def update_handler(update):
            print('[SC Handler] New Secret Chat message!')
            print(update)

            # wait for the main function to get the secret chat id the first time
            global waiting_for_secret_chat_id
            if not waiting_for_secret_chat_id.is_set():
                waiting_for_secret_chat_id.wait()

            global secret_chat_id

            # check if the secret chat is the wanted one
            if update['secret_chat']['user_id'] == RECEIVER_ID and update['secret_chat']['id'] == secret_chat_id:
                if update['secret_chat']['state']['@type'] == 'secretChatStatePending':
                    print("[SC Handler] Secret Chat Pending...")
                if update['secret_chat']['state']['@type'] == 'secretChatStateReady':
                    print("[SC Handler] Secret Chat Ready!")
                    global waiting_for_secret_chat
                    waiting_for_secret_chat.set()

        # add handler
        tg.add_update_handler("updateSecretChat", update_handler)

        result = tg.call_method("createNewSecretChat", params={"user_id": RECEIVER_ID})
        result.wait()
        if result.update is None:
            raise Exception("[Main] SC Establishment - Result is None")
        if DEBUG: print("[Main] SC result:\n{}".format(result.update))

        waiting_for_secret_chat_id.set()

        secret_chat_id = result.update['type']['secret_chat_id']
        if DEBUG: print("[Main] SC ID:\n{}".format(secret_chat_id))

        chat_id = result.update['id']

        # wait until the secret chat is established
        waiting_for_secret_chat.wait()

        print("[Main] Secret Chat establishing Phase finished")
    else:
        chat_id = RECEIVER_ID


    """
    @coroutine
    def tg_receiver():
        #global received
        while True:
            # Receive message from telegram, this includes ALL messages
            msg = (yield)
            # Check if it is an actual "message" message and if the sender is our peer
            #print("Message:\n")
            #print(msg)
            if (
                    msg is not None and
                    msg['event'] == str('message') and #TODO: change for document accept
                    not msg['own'] and
                    msg['sender']['peer_id'] == peer_id
            ):
                ### Document Version

                #first message is a text
                if hasattr(msg, 'text'):
                    if msg.text.startswith("HTTP"):
                        answer = {}
                        parsed_msg = msg.text.split("\n")
                        answer['status_code'] = parsed_msg[0].split(" ")[1]
                        answer['status_message'] = parsed_msg[0].split(" ")[2]
                        # parse header
                        header = {}
                        for header_string in parsed_msg[1:]:
                            if header_string != "":
                                header_name, header_value = header_string.split(": ", 1)
                                header[header_name] = header_value
                        answer['header'] = header
                        # TODO: cookies
                        receiver_queue.put(("meta", answer))

                elif hasattr(msg, 'media') and msg['media']['type'] == "document":
                    # get msg id and laod document
                    downloaded_filepath = sender.load_document(msg.id)
                    receiver_queue.put(("document_file_path", downloaded_filepath))
                else:
                    pass
    """

    def message_handler(update):
        if update['message']['date'] < handler_start_time:
            if DEBUG: print('[Message Handler] Discarding old message')
        elif update['message']['is_outgoing']:
            if DEBUG: print("[Message Handler] Discarding own message")
        elif update['message']['sender_user_id'] != RECEIVER_ID:
            if DEBUG: print('[Message Handler] Discarding message from unknown sender')
        else:
            # check if its' normal text:
            # TODO: what happens to normal text answers?
            if update['message']['content']['@type'] == 'messageText':
                text = update['message']['content']['text']['text']
                if DEBUG: print("[Message Handler] Received message with the following text: {}".format(text))
            # check if it's a document:
            elif update['message']['content']['@type'] == 'messageDocument':
                # Extract caption text
                if DEBUG: print("[Message Handler] Document Message:\n{}".format(update))
                text = update['message']['content']['caption']['text']
                if DEBUG: print("[Message Handler] Caption: {}".format(text))

                # get file id and download the file
                file_id = update['message']['content']['document']['document']['id']
                if DEBUG: print("[Message Handler] File id: {}".format(file_id))
                document_result = tg.call_method("downloadFile",
                                                 params={"file_id": file_id, 'priority': 32,
                                                         'offset': 0, 'limit': 0, 'synchronous': True})

                answer = {}
                parsed_msg = text.split("\n")
                answer['status_code'] = parsed_msg[0].split(" ")[1]
                answer['status_message'] = parsed_msg[0].split(" ")[2]
                # parse header
                header = {}
                for header_string in parsed_msg[1:]:
                    if header_string != "":
                        header_name, header_value = header_string.split(": ", 1)
                        header[header_name] = header_value
                answer['header'] = header
                # TODO: cookies
                receiver_queue.put(("meta", answer))

                document_result.wait()
                if DEBUG: print("[Message Handler] Download document answer: ".format(document_result.update))
                path = document_result.update['local']['path']
                if DEBUG: print("[Message Handler] File path of downloaded file: {}".format(path))
                receiver_queue.put(("document_file_path", path))


    # start the message handler
    handler_start_time = time.time()
    tg.add_message_handler(message_handler)


    def tdlib_sender():
        while True:
            # TODO: adjust for desired behaviour
            if DEBUG: print("[Sender] Sender waiting for queue input")
            data = sender_queue.get()
            if DEBUG: print("[Sender] Received Element")
            send_result = tg.send_message(chat_id, data)
            send_result.wait()
            if send_result is None:
                raise Exception("[Sender] Result of sended message was None")
            if DEBUG: print("[Sender] Sended message: {}".format(send_result.update))


    send_worker = threading.Thread(target=tdlib_sender)
    send_worker.setDaemon(True)
    send_worker.start()


    #TODO: empty queues here?

    app.run(port=42069, debug=True, use_reloader=False)
