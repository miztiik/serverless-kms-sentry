# -*- coding: utf-8 -*-
"""
.. module: Monitor certain KMS actions through Cloudtrail and alert in Slack
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
        global_vars['tag_name']                 = "serverless_kms_sentry"
        # global_vars['sentry_borders']          = { "event_names": [ "CreateAlias", "CreateGrant", "CreateKey", "Decrypt", "DeleteAlias", "DescribeKey", "DisableKey", "EnableKey", "Encrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateRandom", "GetKeyPolicy", "ListAliases", "ListGrants", "ReEncrypt" ]}
        global_vars['sentry_borders']           = { "event_names": [ "CreateKey", "CreateAlias", "DeleteAlias", "DisableKey"]}
        global_vars['slack_webhook_url']        = os.environ.get("SLACK_WEBHOOK_URL")
        global_vars['status']                   = True
    except Exception as e:
        logger.error("Unable to set Global Environment variables. Exiting")
        global_vars['error_message']            = str(e)
    return global_vars

def match_event(global_vars, event):
    """
    Check if the event is part of the sentry borders to be patrolled

    :param global_vars: The list of global variables
    :param type: json
    :param event: The lambda event
    :param type: json   

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    resp = {'status': False, 'pay_load':[], 'error_message': ''}
    # Check if we are supposed to monitor this event
    if event.get('detail').get('eventName') in global_vars.get('sentry_borders').get('event_names'):
        tmp = {}
        tmp["account"]          = event.get('account')
        tmp["actor"]            = event.get('detail').get('userIdentity').get('userName')
        tmp["actor_arn"]        = event.get('detail').get('userIdentity').get('arn')
        tmp["actor_type"]       = event.get('detail').get('userIdentity').get('type')
        tmp["actor_region"]     = event.get('detail').get('awsRegion')
        tmp["event_source"]     = event.get('detail').get('eventSource')
        tmp["event_name"]       = event.get('detail').get('eventName')
        tmp["event_time"]       = event.get('detail').get('eventTime')
        tmp["event_epoch_time"] = dateutil.parser.parse( event.get('detail').get('eventTime') ).timestamp()
        tmp["resources"]        = event.get('detail').get('resources')
        tmp["color"]            = "#F35A00"
        resp['pay_load'].append( tmp )
        resp["status"] = True
    else:
        resp['error_message'] = "Event triggered, But couldn't parse event details correctly or unmatched event"
    return resp

def post_to_slack(slack_webhook_url, slack_data):
    """
    Post message to given slack channel/url

    :param slack_webhook_url: The lambda event
    :param type: str
    :param slack_data: A json containing slack performatted text data
    :param type: json

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    resp = {'status': False}
    slack_msg = {}
    slack_msg["text"] = ''
    slack_msg["attachments"] = []
    logger.info(slack_data)
    for i in slack_data.get("pay_load"):
        tmp = {}
        tmp["fallback"]         = "Monitored Action detected."
        tmp["color"]            = i.get("color")
        tmp["pretext"]          = f"Cloudtrail detected KMS event in `{i.get('actor_region')}` region from Account:`{i.get('account')}`"
        tmp["author_name"]      = "Serverless KMS Sentry"
        tmp["author_link"]      = "https://github.com/miztiik/serverless-kms-sentry"
        tmp["author_icon"]      = "https://avatars1.githubusercontent.com/u/12252564?s=400&u=20375d438d970cb22cc4deda79c1f35c3099f760&v=4"
        tmp["title"]            = f"KMS Action: {i.get('event_name')}"
        tmp["title_link"]       = f"https://console.aws.amazon.com/kms/home?region={i.get('actor_region')}#/kms/keys"
        tmp["fields"]           = [
                    {
                        "title": "UserName",
                        "value": f"`{i.get('actor')}`",
                        "short": False
                    },
                    {
                        "title": "UserType",
                        "value": f"`{i.get('actor_type')}`",
                        "short": False
                    },
	    			                {
                        "title": "UserARN",
                        "value": f"`{i.get('actor_arn')}`",
                        "short": False
                    }
                ]
        tmp["footer"]           = "AWS KMS"
        tmp["footer_icon"]      = "https://raw.githubusercontent.com/miztiik/serverless-kms-sentry/master/images/kms_icon.png"
        tmp["ts"]               = int(i["event_epoch_time"])
        tmp["mrkdwn_in"]        = ["pretext", "text", "fields"]
        slack_msg["attachments"].append(tmp)
    logger.info( json.dumps(slack_msg, indent=4, sort_keys=True) )

    # slack_payload = {'text':json.dumps(i)}
    try:
        p_resp = requests.post( slack_webhook_url, data=json.dumps(slack_msg), headers={'Content-Type': 'application/json'} )
        resp["status"] = True
    except Exception as e:
        logger.error( f"ERROR:{str(e)}" )
        resp["error_message"] = f"ERROR:{str(e)}"
    if p_resp.status_code < 400:
        logger.info(f"INFO: Message posted successfully. Resonse:{p_resp.text}")
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
        if global_vars.get("slack_webhook_url"):
            post_to_slack(global_vars.get("slack_webhook_url"), e_resp )
            # Add to return resp the payload
            resp["pay_load"] = e_resp.get("pay_load")
        else:
            logger.info(f"Slack Webhook URL not mentioned/not valid. URL:{global_vars.get('slack_webhook_url')}")
        # All good so far, set status True
        resp["status"] = True
    else:
        resp['error_message'] = e_resp['error_message']
    return resp

if __name__ == '__main__':
    lambda_handler(None, None)