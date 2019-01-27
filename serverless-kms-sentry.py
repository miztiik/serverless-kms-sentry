#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
.. module: To create encrypt/decrypt data with KMS CMKs
    :platform: AWS
    :copyright: (c) 2019 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

from __future__ import print_function
import boto3
import os
import dateutil.parser
import json
import logging
from botocore.vendored import requests
from botocore.client import ClientError

# Initialize Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def set_global_vars():
    """
    Set the Global Variables
    If User provides different values, override defaults

    This function returns the AWS account number

    :return: global_vars
    :rtype: dict
    """
    global_vars = {'status': False}
    try:
        global_vars['Owner']                    = "Mystique"
        global_vars['Environment']              = "Prod"
        global_vars['aws_region']               = "us-east-1"
        global_vars['tag_name']                 = "serverless_kms_sentry"
        # global_vars['sentry_boundary']          = { "event_names": [ "CreateAlias", "CreateGrant", "CreateKey", "Decrypt", "DeleteAlias", "DescribeKey", "DisableKey", "EnableKey", "Encrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateRandom", "GetKeyPolicy", "ListAliases", "ListGrants", "ReEncrypt" ]}
        global_vars['sentry_borders']           = { "event_names": [ "CreateAlias", "DeleteAlias", "DisableKey"]}
        global_vars['webhook_url']              = os.environ.get("WEBHOOK_URL")
        global_vars['status']                   = True
    except Exception as e:
        logger.error("Unable to set Global Environment variables. Exiting")
        global_vars['error_message']            = str(e)
    return global_vars

def match_event(global_vars, event):
    """
    Check if the event is part of the sentry borders to be patrolled

    :param event: The lambda event
    :param type: json

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    resp = {'status': False}
    # Check if we are supposed to monitor this event
    if event.get('detail').get('eventName') in global_vars.get('sentry_borders').get('event_names'):
        resp["pay_load"] = {}
        resp["pay_load"]["account"]         = event.get('account')
        resp["pay_load"]["actor"]           = event.get('detail').get('userIdentity').get('userName')
        resp["pay_load"]["actor_arn"]       = event.get('detail').get('userIdentity').get('arn')
        resp["pay_load"]["actor_region"]    = event.get('detail').get('awsRegion')
        resp["pay_load"]["event_source"]     = event.get('detail').get('eventSource')
        resp["pay_load"]["event_name"]      = event.get('detail').get('eventName')
        resp["pay_load"]["event_time"]      = event.get('detail').get('eventTime')
        resp["pay_load"]["event_epoch_time"]= dateutil.parser.parse( resp["pay_load"]["event_time" ] ).timestamp()
        resp["pay_load"]["resources"]       = event.get('detail').get('resources')
        resp["pay_load"]["color"]           = "#F35A00"
        color = '#7CD197'
        color = '#e2d43b'
        color = '#ad0614'
        resp["status"] = True
    return resp

def post_to_slack(webhook_url, slack_data):
    """
    Post message to given slack channel/url

    :param webhook_url: The lambda event
    :param type: str
    :param slack_data: A json containing slack performatted text data
    :param type: json

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    resp = {'status': False}
    slack_msg = {}
    slack_msg["text"] = f"KMS Operation:{slack_data.get('event_name')} detected in Account:{slack_data.get('account')} in {slack_data.get('actor_region')} region"
    # slack_msg["attachments"] = json.dumps(slack_data, indent=4, sort_keys=True)
    slack_msg["attachments"] = {}
    slack_msg["attachments"]["fallback"]        = slack_msg.get("text")
    slack_msg["attachments"]["color"]           = slack_data.get("color")
    # slack_msg["attachments"]["pretext"]       = f"User:`{slack_data.get('actor')}` performed `{slack_data.get('event_name')}` action."
    slack_msg["attachments"]["author_name"]     = "Serverless-KMS-Sentry"
    slack_msg["attachments"]["author_link"]     = "https://github.com/miztiik"
    slack_msg["attachments"]["author_icon"]     = "https://camo.githubusercontent.com/c141d8a335bed19ba528f8f949fe7a0281da0285/68747470733a2f2f73332e616d617a6f6e6177732e636f6d2f7468702d6177732d69636f6e732d6465762f53656375726974794964656e74697479436f6d706c69616e63655f4157534b4d535f4c415247452e706e67"
    slack_msg["attachments"]["title"]           = f"`{slack_data.get('event_name')}` by user:`{slack_data.get('actor')}`"
    slack_msg["attachments"]["title_link"]      = f"https://console.aws.amazon.com/kms/home?region={slack_data.get('actor_region')}#/kms/keys"
    slack_msg["attachments"]["fields"]          = [
                {
                    "title": "User",
                    "value": slack_data.get('actor'),
                    "short": true
                },
				                {
                    "title": "Action",
                    "value": slack_data.get('event_name'),
                    "short": true
                }
            ]
    slack_msg["attachments"]["footer"]          = "AWS KMS 🛫",
    slack_msg["attachments"]["footer_icon"]     = "https://raw.githubusercontent.com/miztiik/serverless-kms-sentry/master/images/kms_icon.png",
    slack_msg["attachments"]["ts"]              = int(resp["pay_load"]["event_epoch_time"])
    slack_msg["mrkdwn"] = True

    # slack_payload = {'text':json.dumps(slack_data)}
    try:
        p_resp = requests.post( webhook_url, data=json.dumps(slack_msg), headers={'Content-Type': 'application/json'} )
        resp["status"] = True
    except Exception as e:
        logger.error( f"ERROR:{str(e)}" )
        resp["error_message"] = f"ERROR:{str(e)}"
    if p_resp.status_code < 400:
        logger.info(f"INFO: Message posted successfully. {p_resp.text}")
        resp["error_message"] = f"{p_resp.text}"
    elif p_resp.status_code < 500:
        logger.error(f"Unable to post to slack. ERROR: {p_resp.text}")
        resp["error_message"] = f"{p_resp.text}"
    else:
        logger.error(f"Unable to post to slack. ERROR: {p_resp.text}")
        resp["error_message"] = f"{p_resp.text}"
    return resp

def lambda_handler(event, context):
    """
    Entry point for all processing. Load the global_vars

    :return: A dictionary of tagging status
    :rtype: json
    """
    """
    Can Override the global variables using Lambda Environment Parameters
    """
    global_vars = set_global_vars()

    resp = {"status": False, "error_message" : '' }

    if not global_vars.get('status'):
        logger.error('ERROR: {0}'.format( global_vars.get('error_message') ) )
        resp["error_message"] = global_vars.get('error_message')
        return resp

    # Ensure that we have an event name to evaluate.
    if 'detail' not in event or ('detail' in event and 'eventName' not in event['detail']):
        resp["error_message"] = "Lambda not triggered by an event. Does not have any details"
        return resp

    e_resp = match_event(global_vars, event)
    if e_resp.get("status"):
        # Lets post to slack if there is a event
        if global_vars.get("webhook_url"):
            post_to_slack(global_vars.get("webhook_url"), e_resp.get("pay_load"))
        # Add to return resp the payload
            resp["pay_load"] = e_resp.get("pay_load")
        resp["status"] = True
    logger.info(f"Response: {resp}")
    return resp

if __name__ == '__main__':
    lambda_handler(None, None)