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
const extend = require('util')._extend;
const deepcopy = require('deepcopy');
// const myutils = require('./my-utils');


const aclImport = require('./backend_resource/acl-input.js');
// aclImport.acl_import_handler('./test_rules.txt');	// import the acl
aclImport.acl_import_handler('./test_rules_new.txt');	// import the acl
