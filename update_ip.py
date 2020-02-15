#!/usr/bin/python

import requests
import re
import datetime
import json

# Make a regular expression
# for validating an Ip-address
ip_regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''


# noinspection PyBroadException
def get_config():
    try:
        with open('config.json') as json_data_file:
            return json.load(json_data_file)
    except:
        print("Unable to load 'config.json'")
        return None


def validate_config(config):
    has_api_token = "api_token" in config
    has_domain = "domain" in config
    has_record_name = "record_name" in config
    return has_api_token and has_domain and has_record_name


def get_public_ip():
    response = requests.get("https://api.ipify.org/?format=json")
    if response:
        print('Successfully got IP')
        return response.json()['ip']
    else:
        print('Failed retrieving IP')
        return None


def is_valid_ip(ip):
    if re.search(ip_regex, ip):
        print("Valid Ip address: " + ip)
        return True
    else:
        print("Invalid Ip address: " + ip)
        return False


def submit_ip_address(config, public_ip):
    api_token = config["api_token"]
    domain = config["domain"]
    record_name = config["record_name"]

    response = requests.post(
        "https://api.digitalocean.com/v2/domains/" + domain + "/records",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_token
        },
        json={
            "type": "A",
            "name": record_name,
            "data": public_ip,
            "ttl": 3600
        }
    )

    if response:
        print("Successfully updated IP")
    else:
        print("Failed updating IP")


def main():
    now = datetime.datetime.now()
    print("<=== Start Sync ")
    print("Time - " + str(now))

    config = get_config()

    is_valid_config = validate_config(config)

    if not is_valid_config:
        print("Invalid 'config.json'")
        return

    try:
        ip = get_public_ip()
    except:
        print("Connection Failed")
        print("Sync End ==>")
        return

    if not is_valid_ip(ip):
        return

    try:
        submit_ip_address(config, ip)
    except:
        print("Connection Failed")
        print("Sync End ==>")
        return

    print("Sync End ==>")


if __name__ == "__main__":
    main()
