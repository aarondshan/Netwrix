import logging
import re
import os
import requests
import json
import datetime

ts = datetime.datetime.today()

# Create logger. To modify logging level change the level = to INFO, WARN, CRITICAL, DEBUG
logger = logging.getLogger(__name__)
LOG_FORMAT = "%(asctime)s: %(levelname)s: - %(message)s"
logging.basicConfig(format = LOG_FORMAT,filename=r'E:\Netwrix Working Folder\Logs\Netwrix API\iis_logs_log.log',
                    level = logging.INFO)


# Regex to parse client IIS data.
pattern = re.compile(r'^(([0-9])+\-([0-9])+\-([0-9])+)\s((([0-9])+\:([0-9])+\:([0-9])+))\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]'
                     r'{1,3}\.[0-9]{1,3})\s(POST|GET|DELETE|PUT)\s(\S+\s?\S+?\s?\S+\s?\S+?\s?)\-\s(\S+)\s(\S+?)\s'
                     r'(\S+?)\s(\d+\s\d+\s\d+\s\d+)')

# API Header information
headers = {'Contents-Type': 'application/json'}
url = 'https://localhost:9699/netwrix/api/v1/activity_records/?format=json'
logger.info('Starting IIS Log ingestion')
# *.log crawler. To modify location of log file change the information in the following line
# EXAMPLE: "\\172.28.127.235\f$\inetpub\logs"

for root, dirs, files in os.walk(r"\\172.28.100.20\E$\IIS Logs"):
    for file in files:
        if file.endswith(".log"):
            fname = (os.path.join(root, file))

            # Open the *.log files and begin parsing the data
            with open(fname, 'r') as f:
                logger.info(f"Reading logs in {fname}")
                content = f.read().split('\n')

                # Use the regex to separate the data into useful groups that can be ingested into Netwrix
                for line in content:
                    matches = pattern.finditer(line)
                    logger.debug('Separating Data into Match Groups')
                    for match in matches:

                        who = str(match.group(13))
                        objtype = 'IIS LOG'
                        what = str(match.group(12))
                        where = str(match.group(10))
                        when = str(match.group(1) + 'T' + match.group(6) + '-06:00')
                        if match.group(11) == 'GET':
                            action = 'Read'
                        elif match.group(11) == 'Post':
                            action = 'Modify'
                        else:
                            action = 'None'

                        # Create JSON dataframe to dump assigned info
                        logger.debug('Dumping Data into JSON')
                        data = [{
                            'Who': who,
                            'ObjectType': objtype,
                            'Action': action,
                            'What': what,
                            'Where': where,
                            'When': when,
                            'DetailList': [
                                {
                                    'PropertyName': "IIS Log",
                                    'After': str(match.group(0))
                                }
                            ]
                        }]

                        # Using Requests to send API call to Netwrix server to post data
                        logger.info("Sending data to Netwrix host machine.")
                        logger.debug(f'The following data was sent to the Netwrix host: {data}')
                        r = requests.post(url, headers=headers, data=json.dumps(data), auth=('ashannon','!@#QWE0099'),
                                          verify=False)

                        if r.status_code == 200:
                            logger.info(str(data) + 'OK!\n')
                        elif r.status_code == 400:
                            logger.warning(str(data) + 'ERROR: Invalid Request. Check format!\n')
                        elif r.status_code == 401:
                            logger.warning(str(data) + 'ERROR: Unauthorized. Check credentials!\n')
                            break
                        elif r.status_code == 404:
                            logger.warning(str(data) + 'ERROR: Host not found! Check URL in header information.!\n')
                        elif r.status_code == 500:
                            logger.warning(str(r.status_code) + str(data) + 'Error: Server error.\n')
                        else:
                            logger.debug(str(r.status_code) + str(data) + 'UnknownError: An unknown error has occured. '
                                                                          'Check response code.\n')

                logging.info(f'Completed Logging {fname}')
                f.close()
                fpath = f'\\\\172.28.100.20\\e$\\Netwrix Working Folder\\Logs\\Archive\\API Logs\\IIS Logs'
                if not os.path.exists(fpath):
                    logger.info('Archive Directory does not exist. Creating...')
                    os.makedirs(fpath)
                    logger.info(f'Moving {file} to Archive Directory')
                    os.rename(fname,fpath+'\\'+f"{datetime.datetime.now():%Y%m%d_%H%M%S%f}.log")
                    logger.debug(f'File renamed to {datetime.datetime.now():%Y%m%d_%H%M%S%f}.log')
                else:
                    logger.info(f'Moving {file} to Archive Directory')
                    os.rename(fname,fpath+'\\'+f"{datetime.datetime.now():%Y%m%d_%H%M%S%f}.log")
                    logger.debug(f'File renamed to {datetime.datetime.now():%Y%m%d_%H%M%S%f}.log')
