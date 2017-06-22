/**
	MAXNUMBER 		define constant
	MaxNumber 		variable
	maxNumber 		variable
	maxnumber 		variable
	max_number 		function
	Max_Number 		function
**/

/**
	Reset		= "\x1b[0m"
	Bright		= "\x1b[1m"
	FgRed		= "\x1b[91m"
	FgGreen		= "\x1b[92m"
	FgYellow	= "\x1b[93m"
	FgPurple	= "\x1b[95m"
	FgCyan		= "\x1b[96m"
	BgRed		= "\x1b[101m"
	BgBlue		= "\x1b[104m"
	BgPurple	= "\x1b[105m"
**/


const util = require('util');
const deepcopy = require('deepcopy');
const fs = require('fs');




let type = ['Intensive', 'Loose'];
// number of rules generate, from 100 to 1000
let ruleNumber = [];
for (let i=0; i<10; i++) {
	ruleNumber[i] = (i + 1) * 100;
}

for (let i=0; i<type.length; i++) {
	for (let j=0; j<ruleNumber.length; j++) {
		let filename = `rule_${type[i]}_${ruleNumber[j]}.txt`;
		console.log(filename);
	}
}



let in_out = ['INPUT', 'OUTPUT'];
let action = ['ACCEPT', 'DENY'];
let flag = ['SYN', 'SYN,ACK', 'ACK', 'FIN', 'ACK,FIN', 'RST'];

ruleFormate = `iptables -A INPUT -i eth0 -p tcp -s 192.168.1.0/24 -d 192.168.1.0/24 -j ACCEPT`

for (let i=0; i<10; i++)
	console.log( getRandom(0,10) % 2 );


for (let i=0; i<100; i++)
	console.log( getRandom(0,255) );





function getRandom(min, max) {
  return Math.floor(Math.random() * (max - min) + min );
}