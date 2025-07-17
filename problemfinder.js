//THE BASE JAVASCRIPT CODE FOR THE PROBLEM FINDER
//Written By. Keisha Geyrozaga
//This code reads a log file, processes the data to find the most common IPS, most suspicious IPs, and most used endpoints

// Upd. Had to move several files, delete a couple, and add a few more to make the code work properly as I was using an old build as ref
// Upd.2 Made the code more readable and added comments to explain each part succinctly, w/newlines to separate sections when outputted to terminal

const fs = require('fs');
const path = require('path');
//imports the required modules

const logPath = path.join(__dirname, 'sample-log.log');
//specifies the path to the log file
if (!fs.existsSync(logPath))
//checks if the log file exists
{
  console.error('Sorry! This file was not found!');
  process.exit(1);
}

const logs = fs.readFileSync(logPath, 'utf-8').split('\n');
//reads the log file and splits it into an array of lines

const ipStats = {};
const endpointCounts = {};
const suspiciousIPs = new Set();
//initialises objects to store IP statistics, endpoint counts, and suspicious IPs

const logRegex = /(\d{1,3}(?:\.\d{1,3}){3}) - (\w{2}) - \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (.*?) HTTP.*?" (\d{3})/;
//relies on standard log format == 1.2.3.4 - US - [01/07/2025:12:34:56] "GET /api/episodes HTTP/1.1" 200

for (const line of logs) 
//iterates through each line of the log file
{
  const match = line.match(logRegex); //applies the regex to extract relevant data
  
  if (!match) continue;
  //if the line does not match the regex, it skips to the next line
  
  const [_, ip, country, timestamp, method, endpoint, status] = match;
  //destructures the match to extract IP, country, timestamp, method, endpoint, and status

  const time = new Date(timestamp.replace(/:/, ' '));
  //converts the timestamp to a Date object

  if (!ipStats[ip]) ipStats[ip] = []; //initialises the IP entry if it does not exist
  ipStats[ip].push(time); //adds the timestamp to the IP's request history

  endpointCounts[endpoint] = (endpointCounts[endpoint] || 0) + 1;
  //increments the count for the endpoint, initialising it if it does not exist
}

for (const [ip, times] of Object.entries(ipStats))
//iterates through each IP and its request times
{
  times.sort((a, b) => a - b); //sorts the request times for each IP in ascending order
  for (let i = 100; i < times.length; i++)
  //starts checking from the 100th request to see if there are any suspicious patterns
  {
    const timeWindow = (times[i] - times[i - 100]) / 1000;
    //calculates the time difference between the current request and the 100th previous request in seconds
    
    if (timeWindow < 120)
    //if the time difference is less than 120 seconds (2 minutes), it considers the IP suspicious
    {
      suspiciousIPs.add(ip);
      break;
    }
  }
}


console.log("\nMOST COMMON IPS (ORDERED BY REQ COUNT):\n");
//prints the most common IPs ordered by the number of requests
Object.entries(ipStats)
  .sort((a, b) => b[1].length - a[1].length)
  .slice(0, 10)
  .forEach(([ip, reqs]) => console.log(`${ip}: ${reqs.length} requests`));

console.log("\nMOST SUSPICIOUS IPS (ORDERED BY REQ RATE):\n");
//prints the most suspicious IPs based on request rate
[...suspiciousIPs].forEach(ip => console.log(ip));

console.log("\nMOST USED ENDPOINTS (ORDERED BY HITS):\n");
//prints the most used endpoints ordered by the number of hits
Object.entries(endpointCounts)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .forEach(([endpoint, count]) => console.log(`${endpoint}: ${count} hits`));

console.log("\n\nTESTED!\n");
//attempys to add extra newlines to provide space to separate the paragaphs