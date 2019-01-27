# Serverless KMS Sentry
A simple lambda function to monitor _certain_ KMS events through cloudtrail and notify users or security team through slack.

![Fig : Serverless AWS KMS Sentry](https://raw.githubusercontent.com/miztiik/Serverless-GuardDuty-Findings-to-SNS/master/images/Serverless-GuardDuty-Findings-To-SNS.png)

#### Follow this article in [Youtube](https://www.youtube.com/watch?v=OHXDPDc1qEE&list=PLxzKY3wu0_FKok5gI1v4g4S-g-PLaW9YD&index=20)

1. ## Pre-Requisities
    We will need the following pre-requisites to successfully complete this activity,
    1. `Cloudtrail` - [Get help here to setup cloudtrail](https://youtu.be/N4DdqAkeqD4) 
    1. IAM Role - _i.e_ `Lambda Service Role` - _with managed permissions_ [Get Help for setting up IAM Role](https://www.youtube.com/watch?v=5g0Cuq-qKA0&list=PLxzKY3wu0_FLaF9Xzpyd9p4zRCikkD9lE&index=11)
        - `AWSLambdaBasicExecutionRole` - To allow Lambda to log events

1. ## Configure Lambda Function - `Serverless KMS Sentry`
    - The python script is written(_and tested_) in `Python 3.6`.
    - `Copy` the code from `serverless-kms-sentry` in this repo to the lambda function
    - _Optional:_ Add slack `WEBHOOK_URL` in the environment variable
    - `Save` the lambda function
1. ## Configure Lambda Triggers
    Goto the Cloudwatch Dashboard, We are going to use `Event Rules`
    1. Choose `Create a new Rule`
    1. For `Event Source` - Choose `Event pattern`
       1. For `Service`, Choose/Type `KMS`
       1. For `Event Type`, Choose `AWS API Call via CloudTrail`
       1. Choose `Specific Operation(s)`
          1. Add three operations `CreateAlias`, `DeleteAlias`, `DisableKey`
    1. For `Target`, Choose `Lambda Function`
       1. _From dropdown select your Lambda Function Name_
    1. In the bottom, `Configure Details`
    1. Fill the `Rule Name` & `Rule Description`
       1. _Make sure it is **Enabled**_
    1. `Enable` Trigger by `Checking` the box
    1. Click `Save`
    
    Now your lambda function should be triggered when ever there is a KMS event

1. Testing the solution
    Create a new alias for an existing key or delete an key, you should be getting the message in Slack(if configured).