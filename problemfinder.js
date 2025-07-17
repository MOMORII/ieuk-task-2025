const fs = require('fs');
const path = require('path');

const logPath = path.join(__dirname, 'sample-log.log');
if (!fs.existsSync(logPath)) 
{
  console.error('Sorry! This file was not found!');
  process.exit(1);
}

const logs = fs.readFileSync(logPath, 'utf-8').split('\n');

const ipStats = {};
const endpointCounts = {};
const suspiciousIPs = new Set();

//relies on standard log format == 1.2.3.4 - US - [01/07/2025:12:34:56] "GET /api/episodes HTTP/1.1" 200
const logRegex = /(\d{1,3}(?:\.\d{1,3}){3}) - (\w{2}) - \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (.*?) HTTP.*?" (\d{3})/;

for (const line of logs) 
{
  const match = line.match(logRegex);
  if (!match) continue;

  const [_, ip, country, timestamp, method, endpoint, status] = match;

  const time = new Date(timestamp.replace(/:/, ' '));
  //crude but works if properly formatted

  if (!ipStats[ip]) ipStats[ip] = [];
  ipStats[ip].push(time);

  endpointCounts[endpoint] = (endpointCounts[endpoint] || 0) + 1;
}

//flags IPs with over 100 requests in 2 minutes
for (const [ip, times] of Object.entries(ipStats))
{
  times.sort((a, b) => a - b);
  for (let i = 100; i < times.length; i++) 
  {
    const timeWindow = (times[i] - times[i - 100]) / 1000;
    if (timeWindow < 120) 
    {
      suspiciousIPs.add(ip);
      break;
    }
  }
}

//outputs results
console.log("\nMOST COMMON IPS (ORDERED BY REQ COUNT):\n");
Object.entries(ipStats)
  .sort((a, b) => b[1].length - a[1].length)
  .slice(0, 10)
  .forEach(([ip, reqs]) => console.log(`${ip}: ${reqs.length} requests`));

console.log("\nMOST SUSPICIOUS IPS (ORDERED BY REQ RATE):\n");
[...suspiciousIPs].forEach(ip => console.log(ip));

console.log("\nMOST USED ENDPOINTS (ORDERED BY HITS):\n");
Object.entries(endpointCounts)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .forEach(([endpoint, count]) => console.log(`${endpoint}: ${count} hits`));

console.log("\n\nTESTED!\n");
//adds extra newlines to provide space to separate the paragaphs