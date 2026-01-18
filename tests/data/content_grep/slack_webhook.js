const axios = require('axios');

const SLACK_WEBHOOK = 'https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuv123';

function sendSlackNotification(message) {
    axios.post(SLACK_WEBHOOK, {
        text: message
    });
}
