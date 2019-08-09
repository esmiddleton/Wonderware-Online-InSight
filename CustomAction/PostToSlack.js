/* jshint node: true */
/* jshint esversion: 6 */
"use strict";

const DEFAULT_UTC_MINUTES=-7*60;

const https = require('https');

//
// Process an AVEVA Insight "Custom Action" alert
// and post it to Slack
//

/*

	Usage:
	
		https://...?webhook=TM8G....y4&offsetmins=-480&channel=general
	
	Parameters (all are case-sensitive):
	
		webhook		The Web Hook created in Slack (required)
		
		offsetmins	The minutes local time is offset from local time. Due to current
					limitations in the Insight Chart API, this is required to generate
					the chart URL in the message correctly. Defaults to "-480".
					
		channel		Overrides the default channel associated with the Web Hook to direct
					the message to an alternate channel. You may omit the "#" prefix, but
					if it is included it must be URL encoded.
					
						Okay:
								general
								%23general
						
						Wrong:
						
								#general
	
*/

//
// 9-Aug-2019
// E. Middleton
//

exports.handler = (event, context, callback) => {
    if ((event.queryStringParameters !== null) && (event.queryStringParameters.webhook !== null)) { // Parse the query string
        var slackWebHook = event.queryStringParameters.webhook;
        var channel = event.queryStringParameters.channel;
        
        var offsetMins;
        if (event.queryStringParameters.offsetmins !== null) {
            offsetMins = Number(event.queryStringParameters.offsetmins);
        }
        if (isNaN(offsetMins))
            offsetMins = DEFAULT_UTC_MINUTES;
        
        var body;
        try {
            console.log( "Processing new event:\n" + event.body);
            body = JSON.parse( event.body ); // Extract the information from the Custom Action trigger
            var payload;
            try {
                payload = GetSlackMarkdown(body, offsetMins, channel); // Create a message formatted for Slack
                try {
                    PostToSlack( payload, slackWebHook, callback); // Send it to Slack
                } catch (postError) {
                    callback(null, "Error posting:\n" + JSON.stringify(postError));
                }
            } catch (payloadError) {
                callback(null, "Error creating paylod:\n" + JSON.stringify(payloadError));
            }
        } catch (parseError) {
            callback(null, "Error interpretting request:\n" + JSON.stringify(parseError));
        }
    } else {
        console.log("Missing 'webhook' parameter for Slack in the URL");
    }
};

// Construct the message for Slack
function GetSlackMarkdown(body,offsetMins,channel) {
    const tags = body.tags.split(",");
    
    // Get times to use on a chart around the time of the alert
    var start = (new Date());
    start.setMilliseconds(0); /// make the msecs "round"
    start.setTime( start.getTime() - 10 * 60 * 1000); // 10 minutes before
    start.setTime( start.getTime() + offsetMins * 60 * 1000); // Adjust for UTC offset
    var end = new Date( start.getTime() + 15 * 60 * 1000); // 15 minutes duration

    // Create a URL to open a chart for the tags and time period surrounding the alert
    // Example URL: https://online.wonderware.com/explore?tags=Baytown.B100.Pressure,Baytown.B100.Temperature&chartType=LineChart&startTime=2019-08-08T08:30:00.000&endTime=2019-08-30T08:45:00.000
    const chart = "https://online.wonderware.com/explore?tags=" + tags.join(",") + "&chartType=LineChart"
        + "&startTime=" + start.toISOString().substr(0,23)
        + "&endTime=" + end.toISOString().substr(0,23);
    
    // Add an icon
    var icon = ":mag:"; // Default icon
    if (body.optionalparameter !== "") {
        // Do some basic validation of the icon code and then use it. Find codes at https://www.webfx.com/tools/emoji-cheat-sheet
        if ( (body.optionalparameter.length > 4) && (body.optionalparameter.substr(0,1) === ":") && (body.optionalparameter.substr(body.optionalparameter.length-1,1) === ":"))
            icon = body.optionalparameter;
    }

    var tagMarkdown = "";
    tags.forEach(function(tag){
        tagMarkdown += ">" + tag + "\n";
    });

    // Create the message for Slack using the "markdown" format
    const payload =
        {
            username: "AVEVA Insight",
            type: "mrkdwn",
            icon_emoji: icon,
            text: `*${body.name}* triggered an action in _${body.tenantname}_\n>${body.Description}\n<${chart}|View a chart> for the tags used in the alert:\n${tagMarkdown}`
        };
    
    if (channel !== null) {
        if (channel.substr(0,1) === "#") // Can't use a # directly in the URL without URL-encoding it, so supply it if it was missing
            payload.channel = channel;
        else
            payload.channel = "#"+channel;
    }

  return (payload);
}

// Post a message to Slack
function PostToSlack(payload, slackWebHook, callback) {
  const options = {
    hostname: "hooks.slack.com",
    method: "POST",
    path: "/services/" + slackWebHook
  };

  // Send the message
  const req = https.request(options,
      (res) => res.on("data", () => callback(null, "OK")));
  req.on("error", (error) => callback(JSON.stringify(error)));
  req.write(JSON.stringify(payload));
  req.end();
}
