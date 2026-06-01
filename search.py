import configparser
import json
import re
import time
from datetime import datetime
from email.mime.text import MIMEText

import requests

import database
import mail

CONFIG = configparser.ConfigParser()
CONFIG.read("config.ini")


def get_search_result(api_url):
    headers = {"apiKey": CONFIG["DEFAULT"]["apiKey"]}
    resp = requests.get(api_url, headers=headers)
    return resp.json()


def get_result_count(json_file):
    result_count = json_file["totalResults"]
    print("There are " + str(result_count) + " results.")
    return result_count


def get_id_nums(result_count, json_file):
    email_lines = []
    for i in range(result_count):
        email_lines.append(json_file["vulnerabilities"][i]["cve"]["id"])
        email_lines.append("Creation Date: " + json_file["vulnerabilities"][i]["cve"]["published"])
        email_lines.append("Last Modified: " + json_file["vulnerabilities"][i]["cve"]["lastModified"])
        email_lines.append(json_file["vulnerabilities"][i]["cve"]["descriptions"][0]["value"])
        email_lines.append("\n")
    return email_lines


def create_entries(json_file, result_count, formatted_line, email):
    try:
        for i in range(result_count):
            cve_id = json_file["vulnerabilities"][i]["cve"]["id"]
            cve_id = re.sub(r"\D", "", cve_id)
            publish_date = json_file["vulnerabilities"][i]["cve"]["published"]
            datetime_object = datetime.strptime(publish_date, "%Y-%m-%dT%H:%M:%S.%f")
            publish_date = datetime_object.strftime("%Y-%m-%d %H:%M:%S")
            last_modified = json_file["vulnerabilities"][i]["cve"]["lastModified"]
            datetime_object = datetime.strptime(last_modified, "%Y-%m-%dT%H:%M:%S.%f")
            last_modified = datetime_object.strftime("%Y-%m-%d %H:%M:%S")
            description = json_file["vulnerabilities"][i]["cve"]["descriptions"][0]["value"]
            email = database.insert_data(formatted_line, cve_id, publish_date, last_modified, description, email)
    except FileNotFoundError:
        print("There was a problem opening the file, exiting.")
        exit(0)
    finally:
        return email


def format_json(json_file):
    return json.dumps(json_file, sort_keys=True, indent=4)


def timed_search():
    startTime = int(datetime.now().timestamp())
    print(startTime)

    while True:
        if int(datetime.now().timestamp() - startTime) >= int(CONFIG["DEFAULT"]["checkFrequency"]):
            file = CONFIG["DEFAULT"]["txtList"]
            message = ""
            message_length = 0
            try:
                with open(file, "r") as file:
                    for line in file:
                        url = make_keyword_url(line)
                        formatted_line = line.replace(" ", "")
                        database.create_tables(formatted_line)
                        time.sleep(3)
                        json_file = get_search_result(url)
                        result_count = get_result_count(json_file)
                        message = create_entries(json_file, result_count, formatted_line, str(message))
                        message_length += len(message)

                    if message_length > 0:
                        message_formatted = MIMEText("".join(str(message)))
                        email = mail.create_email(
                            CONFIG["EMAIL"]["senderEmail"],
                            CONFIG["EMAIL"]["recipientEmail"],
                            CONFIG["EMAIL"]["subjectLine"],
                            message_formatted,
                        )
                        mail.send_email(
                            CONFIG["EMAIL"]["senderEmail"],
                            CONFIG["EMAIL"]["senderPassword"],
                            email,
                        )
                    else:
                        print("No new CVEs found.")

                    print(url)
            except FileNotFoundError:
                print("There was a problem opening the file, exiting")
                exit(0)
            finally:
                file.close()
                startTime = int(datetime.now().timestamp())


def make_keyword_url(keywords):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + keywords
    return url.replace(" ", "%20")
