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
    
    if not has_api_token:
        print ("missing 'api_token' field")
    if not has_domain:
        print ("missing 'domain' field")
    if not has_record_name:
        print ("missing 'record_name' field")

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


def get_record_id(config):
    api_token = config["api_token"]
    domain = config["domain"]
    record_name = config["record_name"]

    response = requests.get(
        "https://api.digitalocean.com/v2/domains/" + domain + "/records",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_token
        }
    )

    if response:
        json_data = response.json()
        print("Get Records Success (count: " + str(json_data["meta"]["total"]) + ")")
        records = json_data["domain_records"]
        for record in records:
            if record_name == record["name"]:
                return record["id"]
        return None
    else:
        print("Failed getting records")
        return None


def update_record(config, record_id, public_ip):
    api_token = config["api_token"]
    domain = config["domain"]
    record_name = config["record_name"]

    response = requests.put(
        "https://api.digitalocean.com/v2/domains/" + domain + "/records/" + str(record_id),
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
        print("Successfully updating record " + str(record_id))
    else:
        print("Failed updating record " + str(record_id))


def create_record(config, public_ip):
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
        print("Successfully created record")
    else:
        print("Failed creating record")


def main():
    now = datetime.datetime.now()
    print("<=== Start Sync ")
    print("Time - " + str(now))

    config = get_config()

    if not config:
        print("Invalid 'config.json'")
        print("Sync End ==>")
        return

    is_valid_config = validate_config(config)

    if not is_valid_config:
        print("Invalid 'config.json'")
        print("Sync End ==>")
        return

    try:
        ip = get_public_ip()
    except Exception, e:
        print("Error " + str(e))
        print("Sync End ==>")
        return

    if not is_valid_ip(ip):
        return

    record_id = get_record_id(config)

    try:
        if record_id:
            print "Found record with id " + str(record_id)
            update_record(config, record_id, ip)
        else:
            print "No record found creating one"
            create_record(config, ip)
    except Exception, e:
        print("Error " + str(e))
        print("Sync End ==>")
        return

    print("Sync End ==>")


if __name__ == "__main__":
    main()
