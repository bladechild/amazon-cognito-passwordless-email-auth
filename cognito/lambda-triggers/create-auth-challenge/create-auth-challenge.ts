// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CognitoUserPoolTriggerHandler } from 'aws-lambda';
import { randomDigits } from 'crypto-secure-random-digit';
import { SES, SNS } from 'aws-sdk';

const region = 'eu-west-1'
const ses = new SES({ region });
const sns = new SNS({ apiVersion: '2010-03-31', region });

export const handler: CognitoUserPoolTriggerHandler = async event => {

    let secretLoginCode: string;
    if (!event.request.session || !event.request.session.length) {

        // This is a new auth session
        // Generate a new secret login code and mail it to the user
        secretLoginCode = randomDigits(6).join('');
        const email = event.request.userAttributes.email
        const phone = event.request.userAttributes.phone_number
        if(email){
            await sendEmail(email, secretLoginCode);
        }
        if(phone) {
            await sendMessage(phone, secretLoginCode)
        }
    } else {

        // There's an existing session. Don't generate new digits but
        // re-use the code from the current session. This allows the user to
        // make a mistake when keying in the code and to then retry, rather
        // the needing to e-mail the user an all new code again.    
        const previousChallenge = event.request.session.slice(-1)[0];
        secretLoginCode = previousChallenge.challengeMetadata!.match(/CODE-(\d*)/)![1];
    }

    // This is sent back to the client app
    event.response.publicChallengeParameters = { email: event.request.userAttributes.email, phone: event.request.userAttributes.phone_number };

    // Add the secret login code to the private challenge parameters
    // so it can be verified by the "Verify Auth Challenge Response" trigger
    event.response.privateChallengeParameters = { secretLoginCode };

    // Add the secret login code to the session so it is available
    // in a next invocation of the "Create Auth Challenge" trigger
    event.response.challengeMetadata = `CODE-${secretLoginCode}`;

    return event;
};

async function sendEmail(emailAddress: string, secretLoginCode: string) {
    const params: SES.SendEmailRequest = {
        Destination: { ToAddresses: [emailAddress] },
        Message: {
            Body: {
                Html: {
                    Charset: 'UTF-8',
                    Data: `<html><body><p>This is your secret login code:</p>
                           <h3>${secretLoginCode}</h3></body></html>`
                },
                Text: {
                    Charset: 'UTF-8',
                    Data: `Your secret login code: ${secretLoginCode}`
                }
            },
            Subject: {
                Charset: 'UTF-8',
                Data: 'Your secret login code'
            }
        },
        Source: process.env.SES_FROM_ADDRESS!
    };
    await ses.sendEmail(params).promise();
}

async function sendMessage(phone: string, secretLoginCode: string) {
    const params = {
        Message: `Your secret login code: ${secretLoginCode}`, /* required */
        PhoneNumber: phone,
    };
    await sns.publish(params).promise();
}
