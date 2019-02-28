# Serverless KMS Sentry
A simple lambda function to monitor _certain_ KMS events through cloudtrail and notify users or security team through slack.

![Fig : Serverless AWS KMS Sentry](https://raw.githubusercontent.com/miztiik/serverless-kms-sentry/master/images/serverless-kms-sentry.png)

#### Follow this article in [Youtube](https://youtu.be/UYaV-VfnbT8)

1. ## Pre-Requisities
    We will need the following pre-requisites to successfully complete this activity,
    - `Cloudtrail` - [Get help here to setup cloudtrail](https://youtu.be/N4DdqAkeqD4) 
    - IAM Role - _i.e_ `Lambda Service Role` - _with managed permissions_ [Get Help for setting up IAM Role](https://www.youtube.com/watch?v=5g0Cuq-qKA0&list=PLxzKY3wu0_FLaF9Xzpyd9p4zRCikkD9lE&index=11)
        - `AWSLambdaBasicExecutionRole` - To allow Lambda to log events

1. ## Configure Lambda Function - `Serverless KMS Sentry`
    - The python script is written(_and tested_) in `Python 3.7`.
    - `Copy` the code from `serverless-kms-sentry` in this repo to the lambda function
    - _Optional:_ Add slack `SLACK_WEBHOOK_URL` in the environment variable
    - `Save` the lambda function
1. ## Configure Lambda Triggers
    Goto the Cloudwatch Dashboard, We are going to use `Event Rules`
    - Choose `Create a new Rule`
    - For `Event Source` - Choose `Event pattern`
       - For `Service`, Choose/Type `KMS`
       - For `Event Type`, Choose `AWS API Call via CloudTrail`
       - Choose `Specific Operation(s)`
          - Add three operations `CreateAlias`, `DeleteAlias`, `DisableKey`
    - For `Target`, Choose `Lambda Function`
       - _From dropdown select your Lambda Function Name_
    - In the bottom, `Configure Details`
    - Fill the `Rule Name` & `Rule Description`
       - _Make sure it is **Enabled**_
    - `Enable` Trigger by `Checking` the box
    - Click `Save`
    
    Now your lambda function should be triggered when ever there is a KMS event

1. Testing the solution
    Create a new alias for an existing key or delete an key, you should be getting the message in Slack(if configured). If not use the sample event in the repo to test.