/* jshint node: true */
/* jshint esversion: 6 */
"use strict";

const https = require('https');

const ONLINE_HOST = "online.wonderware.com";
const ONLINE_PATH = "/apis/upload/datasource";



function transform(input, offsetMinutes) {
    var compactFormat = (input.lines[0].trim().substr(0,12).toLowerCase()=='gateway name');
    var output;
    if (compactFormat) {
        output=transformCompact( input.lines, offsetMinutes);
    } else {
        output=transformComX( input.lines, offsetMinutes);
    }
    return output;
}

function transformCompact(lines, offsetMinutes) {
    var output = [];
    
    var deviceParts = lines[1].split(",");
    var baseTag = spacesToCamelCase(deviceParts[4]);

    var tags = [];
    var header = lines[6].split(',');
    for (var j=3; j<header.length; j++) {
        tags[j-3] = baseTag+'.'+spacesToCamelCase( stripEU(header[j]) );
    }
    console.log("Tags: " + JSON.stringify(tags));
    
    for (var i = 7; i< lines.length; i++) {
		// Columns Used: 1=UTC Offset Minutes, 2=Local Date/Time, >3 values
		// Columns Ignored: 0=Error
		var cols = lines[i].split(",");
        if (cols.length >= 3) { // If there is a full record
            var cols = lines[i].split(","); // Split lines
            for (var j=0; j<cols.length; j++) // Remove leading/trailing spaces
                cols[j] = cols[j].trim();

            var rowOffsetMinutes = Number.parseInt(cols[1]);
            var t = new Date(cols[2]);
            t.setTime( t.getTime() - (rowOffsetMinutes+offsetMinutes) * 60 * 1000); // Apply a UTC offset

			// Create a record and add it to the output
            var row = {
                dateTime: t
            };
            
            for (var j=3; j<cols.length; j++) {
                row[tags[j-3]] = formatValue(cols[j]);
                output[i-7] = row;
            }
        }
    }
    return output;
}

function transformComX(lines, offsetMinutes) {
    var output = [];
    
    for (var i=1; i< lines.length; i++) {
		// Columns Used: 0=Tag, 1=Description, 3=Date, 4=start/end time, 5=Value
		// Columns Ignored: 2=Utility Label, 6=Estimated Flag, 7=Lead, 8=Lag
        var cols = lines[i].split(","); // Split lines
        for (var j=0; j<cols.length; j++) // Remove leading/trailing spaces
            cols[j] = cols[j].trim();
        
        if (cols.length >= 5) { // If there is a full record

            var start = cols[4].split("-"); // Get the first time from the format "04:30-04:59"
            var t = new Date(cols[3] + " " + start[0]); // Combine the date in the form "01 April 2017" with the time above
            t.setTime( t.getTime() - offsetMinutes * 60 * 1000); // Apply a UTC offset
			
			// Create a record and add it to the output
            var row = {
                dateTime: t
            };
            row[cols[0]] = formatValue(cols[5]); // TagName
            output[i-1] = row;
        }
    }
    return output;
}

function defineCompactTags( input ) {
    var lines = input.split("\n");
    console.log("Parsing meta data");

    var deviceParts = lines[1].split(",");
    var baseTag = spacesToCamelCase(deviceParts[4]);
    var baseDesc = deviceParts[0];

    var tags = [];
    var header = lines[6].split(',');
    for (var j=3; j<header.length; j++) {
        tags[j-3] = {};
        tags[j-3].TagName = baseTag+'.'+spacesToCamelCase( stripEU(header[j]) );
        tags[j-3].Description = baseDesc+' '+ header[j].substr(0,header[j].indexOf('(')-1);
        tags[j-3].EngUnit = parseEU(header[j]);
    }
    return tags;
}

function spacesToCamelCase( withSpaces ) {
    var noSpaces = "";
    withSpaces = withSpaces.trim();
    var c = 0;
    while (c<withSpaces.length) {
    	if ((withSpaces.charAt(c)==' ') && (c<withSpaces.length-1))
            noSpaces += withSpaces.charAt(++c).toUpperCase();
        else
            noSpaces += withSpaces.charAt(c);
    	c++;
    }
    return noSpaces;
}

function parseEU( header ) {
	var open = header.indexOf('(');
	var close = header.indexOf(')');
  if ((open>0) && (close>open))
  	return (header.substring(open+1,close).trim());
  else
  	return ('');
}

function stripEU( header ) {
	var paren = header.indexOf('(');
  if (paren > 0)
  	return (header.substr(0,paren).trim());
  else
  	return (header.trim());

}

function formatValue( x ) {
    var y =  Number.parseInt(x);
    if (isNaN(y)) {
        if ((x.toLowerCase()=='n/a')||(x.toLowerCase()=='null')||(x.toLowerCase()=='nan'))
            y=null;
        else
            y=x;
    }
    return y;
}


function extractInput(body) {
    body = body.replace(/\r/g,'');
    var lines = body.split("\n");

    // Find the first, non-blank line without extra header info
    var firstLine = 0;
    var disposition = [];
    while ((firstLine<lines.length) &&
    	(
      	(lines[firstLine].substring(0,7).toLowerCase()=='content')
    	 ||(lines[firstLine].substring(0,7)=='-------')
		 ||(lines[firstLine].trim().length == 0)
		)) {
	    if (lines[firstLine].toLowerCase().indexOf('content-disposition')>=0)
	        disposition = lines[firstLine].split(';');
		firstLine++;
        }
        
    var results = [];
    for (var i=firstLine;i<lines.length;i++)
        results[i-firstLine]=lines[i];
    
    var filename;
    for (var i=0; i<disposition.length; i++) 
        if (disposition[i].trim().toLowerCase().indexOf('filename')==0) {
            filename=disposition[i].substring(disposition[i].indexOf('"')+1,disposition[i].lastIndexOf('"'));
        }
    
    return ({lines: results, filename: filename});
}

exports.handler = (event, context, callback) => {
    var debug = false;
    if (typeof event.headers["x-debug"] !== 'undefined') {
        debug = (event.headers["x-debug"].toLowerCase() == 'true' );
        console.log("Request debugging set to '" + debug + "'");
    }
    
    var transformOnly = false;
    if (typeof event.headers["x-test"] !== 'undefined') {
        transformOnly = (event.headers["x-test"].toLowerCase() == 'true' );
        console.log("Only Transform set to '" + transformOnly + "'");
    }

    /*
    if (debug) {
        console.log( "event: "+JSON.stringify(event) );
        console.log( "context: "+JSON.stringify(context) );
    }
    */

    
    var responseBody;
    if ((typeof event.headers !== "undefined") && (typeof event.headers.Authorization !== "undefined")) {
        console.log("From: " + event.requestContext.identity.sourceIp + "   Using key: " + event.requestContext.identity.apiKey.substr(0,10) + "...");

        var auth = event.headers.Authorization;
        var token = "";
        if (auth.substr(0,6).toLowerCase()=="bearer") {
            token = auth.substr(7,2000);
            if (debug)
                console.log("Token: " + token.substr(0,10) + "...");
        }
        
        var metadata = false;
        if (typeof event.headers["x-metadata"] !== 'undefined') {
            metadata = (event.headers["x-metadata"].toLowerCase() == 'true' );
            console.log("Uploading metadata");
        }
        
        if (!metadata) {
            var offsetMinutes = 0;
            if (typeof event.headers["x-utc-offset-minutes"] !== 'undefined') {
                offsetMinutes = Number.parseInt(event.headers["x-utc-offset-minutes"]);
                if (debug)
                    console.log("Applying UTC offset of " + offsetMinutes + " minutes");
            }
    
            var input = extractInput(event.body);
            var data = transform(input, offsetMinutes);
            if (debug) {
                console.log("Input: "+JSON.stringify(input));
            }

            var oldest=0;
            var newest=0;
            var total=0;
            var max=0;
            for (var i=0; i<data.length;i++) {
                var d = new Date(data[i].dateTime);
                if (d.getTime() > newest)
                    newest = d.getTime();
                if ((d.getTime() < oldest) || (oldest==0))
                    oldest = d.getTime();
                var count = Object.keys(data[i]).length-1;
                if (count>max)
                    max=count;
                total += count;
            }
            
            var fileInfo = (typeof input.filename != 'undefined' ? 'File "'+input.filename+'" ' : '');
            console.log( fileInfo+"Parsed "+total+" total values for "+max+" tags between "+(new Date(oldest)).toLocaleString()+" and "+(new Date(newest)).toLocaleString() );

            if (debug)
                console.log( "Transformed: "+JSON.stringify(data) );
    
            responseBody = {
                data: data
            };
        } else {
            var data = defineCompactTags(event.body);
    
            responseBody = {
                metadata: data
            };
        }
        
        if (!transformOnly)
            online_post_ajax(token, JSON.stringify(responseBody), (res) => {
                if (debug)
                    console.log( "Post response: "+JSON.stringify(res) );
            });
    } else {
        console.log( "No authorization found");
        console.log( "event: "+JSON.stringify(event) );
        console.log( "context: "+JSON.stringify(context) );
        responseBody = { message: "Authorization token is missing" };
    }
    
    var response = {
        statusCode: 200,
        headers: {
        },
        body: (debug ? JSON.stringify(responseBody) : "OK")
    };
    
    if (debug)
        console.log("Response: " + JSON.stringify(response));
    callback(null, response);
};

function online_post_ajax(token, body, callback) {
    var options = {
        'hostname': ONLINE_HOST,
        'headers' : {
            'Authorization' : 'Bearer ' + token,
            'Content-Type' : 'application/json',
            'Content-Length': body.length,
            'Cache-Control' : 'no-cache'
        },
        'port' : 443,
        'path' : ONLINE_PATH,
        'method' : 'POST'
    };

    var req = https.request(options, (res) => {
        var all_data = "";
        res.on('data',(d)=>{
            console.log('POST Data: ' + JSON.stringify(d));
            all_data += d;
        });
        res.on('error',(e)=>{
            console.log('POST Error: '+ JSON.stringify(e));
            callback({error:true});
        });
        res.on('end',()=>{
            if (all_data.length>0)
                console.log('Online Response:'+ all_data);
            else
                console.log('Posted, empty response.');
        });
    });
    req.write(body);
    req.end();
}
