import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import logging
import threading
import time
import io
from multiprocessing import Queue
from urllib.parse import urlparse, parse_qs
import requests
import subprocess
import os

# The poller starts with a sleep time of CHANGE_POLLER_SLOW_INTERVAL between each poll request.
# If the poller gets' a successful change poll it's switches the sleep time to CHANGE_POLLER_FAST_INTERVAL.
# After CHANGE_POLLER_THROTTLE_CYCLE number of unsuccessful change polls it switches back to
# CHANGE_POLLER_SLOW_INTERVAL sleep time.
# Therefore it the poller polls fast for CHANGE_POLLER_FAST_INTERVAL*CHANGE_POLLER_THROTTLE_CYCLE seconds and is
# doing 1/CHANGE_POLLER_FAST_INTERVAL number of requests per seconds during this time.
#
# The change poller can be started and stopped with the event:
#     change_poller_stop_event
#     change_poller_run_event
#
# If the change poller is stopped and then restarted the counter for the CHANGE_POLLER_THROTTLE_CYCLE resets

CHANGE_POLLER_FAST_INTERVAL = 0.125
CHANGE_POLLER_SLOW_INTERVAL = 0.125
CHANGE_POLLER_THROTTLE_CYCLE = 200

INCOMING_FOLDER = 'HTTP_Request'
OUTGOING_FOLDER = 'HTTP_Response'

# If the not run in parralel mode, the server just processes one request at a time.
# PARALLEL NOT TESTED.
PARALLEL = False

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

## Setup logger ##
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def authenticate_and_build_service():
    # If modifying these scopes, delete the file server_token.pickle.
    scopes = ['https://www.googleapis.com/auth/drive']

    creds = None
    # The file server_token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('server_token.pickle'):
        with open('server_token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'server_credentials.json', scopes)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('server_token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('drive', 'v3', credentials=creds)


def change_poller():
    # see thread safety, each thread needs their own service
    gdrive_service = authenticate_and_build_service()
    # TODO: test or change to APScheduler for python?
    global change_poller_run_event
    global change_poller_stop_event

    throttled = True

    if change_poller_stop_event.is_set():
        change_poller_stop_event.clear()

        print("[Change Poller] Stopped before first start...")

        change_poller_run_event.wait()
        change_poller_run_event.clear()

        print("[Change Poller] Started first time...")

    print("[Change Poller] Getting Start Page Token for changes")
    response = gdrive_service.changes().getStartPageToken().execute()
    print("[Change Poller] Start Page token response: {}".format(response))

    saved_start_page_token = response.get('startPageToken')

    fast_cycles = 0

    while True:
        change_poller_run_event.clear()

        page_token= saved_start_page_token
        while page_token is not None:
            print("[Change Poller] Polling for changes...")
            # start_time = time.time()
            response = gdrive_service.changes().list(pageToken=page_token,
                                                     pageSize=1000,
                                                     spaces='drive').execute()
            # print("Execution time for change request: {}".format(start_time-time.time()))
            print("[Change Poller] Change list response:\n{}".format(response))
            for change in response.get('changes'):
                # Process change
                file_id = change.get('fileId')

                if change['removed'] == 'True':
                    print('[Change Polller] Ignoring removed file {}'.format(change['fileId']))

                elif change['file']['name'].startswith('request'):
                    print('[Change Poller] Change found for file {} -> putting into downloader queue'.format(file_id))
                    print("[Change Poller] Time: {}".format(time.time()))
                    downloader_queue.put(file_id)

                    # if the change poller is throttled, unthrottle it
                    fast_cycles = 0
                    if throttled:
                        print('[Change Polller] Unthrottling due to found change')
                        throttled = False
                else:
                    print('[Change Polller] Ignoring unrelevant file {}'.format(change['file']['name']))

            if 'newStartPageToken' in response:
                # Last page, save this token for the next polling interval
                print("[Change Poller] No changes left -> adjusting start page token")
                saved_start_page_token = response.get('newStartPageToken')
            page_token = response.get('nextPageToken')

        if throttled:
            sleep_time = CHANGE_POLLER_SLOW_INTERVAL
        else:
            sleep_time = CHANGE_POLLER_FAST_INTERVAL
        print("[Change Poller] Sleeping for {} seconds...".format(sleep_time))
        time.sleep(sleep_time)

        if not throttled:
            fast_cycles += 1
            # if the maximum number of fast cycles is reached throttle the poller
            if fast_cycles == CHANGE_POLLER_THROTTLE_CYCLE:
                throttled = True

                print("[Change Poller] Throttling!")

        if change_poller_stop_event.is_set():
            change_poller_stop_event.clear()

            print("[Change Poller] Stopped...")

            change_poller_run_event.wait()
            change_poller_run_event.clear()
            throttled = False

            print("[Change Poller] Restarted...")


def downloader():
    # see thread safety, each thread needs their own service
    gdrive_service = authenticate_and_build_service()
    while True:
        print("[Downloader] Downloader waiting for queue input")
        downloadfile_id = downloader_queue.get()

        if not PARALLEL:
            print("[Downloader] NOT PARRALEL: Stopping change poller...")
            change_poller_stop_event.set()


        print("[Download] Download file with the ID: {}".format(downloadfile_id))
        # TODO: abuse check only when the file is flagged as potential abuse, nevertheless unlikely
        request = gdrive_service.files().get_media(fileId=downloadfile_id)
        fh = io.BytesIO()
        # TODO: download type
        print("[Downloader] Time: {}".format(time.time()))
        media_downloader = MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = media_downloader.next_chunk()
            print("[Downloader] Download {}".format(int(status.progress() * 100)))

        # Set the stream position back to the beginning for reading
        fh.seek(0)
        # read content and convert it to a string because it's the request
        content = fh.read().decode('UTF-8')

        print("[Downloader] Time: {}".format(time.time()))
        print("[Downloader] The following was downloaded to memory(Length: {}):\n{}".format(fh.getbuffer().nbytes, content))

        executer_queue.put(content)
        fh.close()


def request_executer():
    def return_error(error_content):
        error_answer_string = "HTTP/1.1 569 TUNNEL_ERROR\n" \
                        "Content-Type: text/html; charset=utf-8"

        if type(error_content) is str:
            error_content = error_content.encode('utf-8')

        answer_queue.put((error_answer_string, error_content))

    while True:
        # TODO: adjust for desired behaviour
        print("[Request Executer] Waiting for queue input")
        message = executer_queue.get()
        print("[Request Executer] Preparing message for requests library")
        print("[Request Executer] Time: {}".format(time.time()))
        # take the HTTP query and prepare it for the requests library
        message = message.strip().split('\n')
        print(message)
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

            with open(one_page_file_name, "rb") as f:
                content = f.read().strip()

            answer_string = "HTTP/1.1 200 OK\n" \
                            "Content-Type: text/html; charset=utf-8"

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
            print("[Request Executer] Time: {}".format(time.time()))
            # execute the query
            response = requests.request(method, url, params=parameters)

            print("[Request Executer] Time: {}".format(time.time()))
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
            #print("[Request Executer] HTTP answer headers\n{}".format(response.headers))
            # TODO: this a workaround, because the chunked transportation doesnt apply for the client
            # TODO: research which header are important?
            for header_name in response.headers:
                if header_name == "Transfer-Encoding" or header_name == 'Content-Encoding':
                    continue
                answer_string += "{header_name}: {header_value}\n".format(
                    header_name=header_name,
                    header_value=response.headers[header_name]
                )

            #print("[Request Executer] Response Content: {}".format(response.content))
            print("[Request Executer] Time: {}".format(time.time()))

            content = response.content

        # IDEA: give the sender the binary content and answer string
        # so the binary doesn't needs to be written to a file

        #print("[Request Executer] Answer string:\n{}".format(answer_string))
        answer_queue.put((answer_string, content))


def sender():
    # see thread safety, each thread needs their own service
    gdrive_service = authenticate_and_build_service()
    while True:
        # TODO: adjust for desired behaviour
        print("[Sender] Sender waiting for queue input")
        header, payload = answer_queue.get()

        """
        FORMAT of the response:
        First line is a number which indicates how many of the following lines are a part of the HTTP answer header
        Then the specified amount of header lines follows
        After the a last line break occurs and then the payload follows
        
        Example:
        3
        HTTP/1.1 200 OK
        Content-Length: ...
        X-Powered-By: PHP/5.3.1
        [Payload]
        """

        header = header.strip()
        #print("[Sender] Received Header String:\n{}".format(header))

        header = "{nr_of_header_lines}\n{header}\n".format(nr_of_header_lines=len(header.split('\n')),
                                                           header=header)

        print("[Sender] Header of uploaded file:\n{}".format(header))

        file_metadata = {'name': 'response' + str(int(time.time())), 'parents': [outgoing_folder_id]}

        fh_upload = io.BytesIO()
        fh_upload.write(header.encode('utf-8'))
        fh_upload.write(payload)

        # just use 'application/octet-stream' as the mime type. Google doesn't need to know the mime type...
        media = MediaIoBaseUpload(fh_upload, 'application/octet-stream')

        print("[Sender] Starting upload file...")
        print("[Sender] Time: {}".format(time.time()))
        uploadfile = gdrive_service.files().create(body=file_metadata, media_body=media).execute()

        print("[Sender] Upload file response:".format(uploadfile))
        print("[Sender] Time: {}".format(time.time()))

        fh_upload.close()
        if not PARALLEL:
            print("[Sender] NOT PARRALEL: Restarting change poller...")
            change_poller_run_event.set()




if __name__ == '__main__':

    if ONEFILE:
        if not os.path.exists("webpage2html.py"):
            raise Exception("[Main] webpage2html.py not found")

    print("[Main] Starting authentication")
    service = authenticate_and_build_service()
    print("[Main] Authenticated")

    """
    Get folder ids
    """
    print("[Main] Gettings the 100 first root files and folders")
    results = service.files().list(
        pageSize=1000, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])

    print("[Main] Retrieved Files:\n{}".format(items))

    print("[Main]  Searching for outgoing folder({}) and incoming folder({})".format(OUTGOING_FOLDER, INCOMING_FOLDER))

    outgoing_folder_id = None
    incoming_folder_id = None

    for cur_item in items:
        if cur_item['name'] == OUTGOING_FOLDER:
            outgoing_folder_id = cur_item['id']
        elif cur_item['name'] == INCOMING_FOLDER:
            incoming_folder_id = cur_item['id']
        if (outgoing_folder_id is not None) and (incoming_folder_id is not None):
            break

    if outgoing_folder_id is None:
        raise Exception("[Main] Outgoing folder not found")
    if incoming_folder_id is None:
        raise Exception("[Main] Incoming folder not found")

    print("[Main] Ids found:\nOutgoing folder: {}\nIncoming folder: {}".format(outgoing_folder_id, incoming_folder_id))

    """
    Init queues
    """
    downloader_queue = Queue()
    executer_queue = Queue()
    answer_queue = Queue()

    """
    Init Change poller
    """

    change_poller_stop_event = threading.Event()
    change_poller_run_event = threading.Event()

    change_poll_worker = threading.Thread(target=change_poller, args=())
    change_poll_worker.setDaemon(True)
    change_poll_worker.start()

    change_poll_worker = threading.Thread(target=downloader, args=())
    change_poll_worker.setDaemon(True)
    change_poll_worker.start()

    change_poll_worker = threading.Thread(target=request_executer, args=())
    change_poll_worker.setDaemon(True)
    change_poll_worker.start()

    change_poll_worker = threading.Thread(target=sender, args=())
    change_poll_worker.setDaemon(True)
    change_poll_worker.start()



    while True:
        pass