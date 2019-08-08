/* jshint node: true */
/* jshint esversion: 6 */
"use strict";

const MY_KEY="TM...QzgX1";
const UTC_MINUTES=-7*60;

const https = require('https');

// Process an AVEVA Insight "Custom Action" alert
// and post it to Slack
//
// 8-Aug-2019
// E. Middleton
//
exports.handler = (event, context, callback) => {
    var body;
    try {
        console.log( "Processing new event:\n" + event.body );
        body = JSON.parse( event.body ); // Extract the information from the Custom Action trigger
        var payload;
        try {
            payload = GetSlackMarkdown(body); // Create a message formatted for Slack
            //console.log(JSON.stringify(payload));
            try {
                PostToSlack( payload, callback); // Send it to Slack
            } catch (postError) {
                callback(null, "Error posting:\n" + JSON.stringify(postError));
            }
        } catch (payloadError) {
            callback(null, "Error creating paylod:\n" + JSON.stringify(payloadError));
        }
    } catch (parseError) {
        callback(null, "Error interpretting request:\n" + JSON.stringify(parseError));
    }

};

// Construct the message for Slack
function GetSlackMarkdown(body) {
    const tags = body.tags.split(",");
    
    // Get times to use on a chart around the time of the alert
    var start = (new Date());
    start.setMilliseconds(0); /// make the msecs "round"
    start.setTime( start.getTime() - 10 * 60 * 1000); // 10 minutes before
    start.setTime( start.getTime() + UTC_MINUTES * 60 * 1000); // Adjust for UTC offset
    var end = new Date( start.getTime() + 15 * 60 * 1000); // 15 minutes duration
    
    // Create a URL to open a chart for the tags and time period surrounding the alert
    // Example URL: https://online.wonderware.com/explore?tags=Baytown.B100.Pressure,Baytown.B100.Temperature&chartType=LineChart&startTime=2019-08-08T08:30:00.000&endTime=2019-08-30T08:45:00.000
    const chart = "https://online.wonderware.com/explore?tags=" + tags.join(",") + "&chartType=LineChart"
        + "&startTime=" + start.toISOString().substr(0,23)
        + "&endTime=" + end.toISOString().substr(0,23);
    
    // Create the message for Slack using the "markdown" format
    const payload =
        {
            type: "mrkdwn",
            text: `*${body.name}* triggered an action\n>${body.Description}\n>In solution _${body.tenantname}_\nThe alert is based on:\n${tags.join("\n")}\n><${chart}|See chart>`
        };

  return (payload);
}

// Post a message to Slack
function PostToSlack(payload, callback) {
  const options = {
    hostname: "hooks.slack.com",
    method: "POST",
    path: "/services/" + MY_KEY
  };

  // Send the message
  const req = https.request(options,
      (res) => res.on("data", () => callback(null, "OK")));
  req.on("error", (error) => callback(JSON.stringify(error)));
  req.write(JSON.stringify(payload));
  req.end();
}
