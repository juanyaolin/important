const Getopt = require('node-getopt').create([
		['A', '=' 				, 'append rule to table option.'],
		['I', '=' 				, 'insert rule to table option.'],
		['i', '=' 				, 'interface to set inbound option.'],
		['o', '=' 				, 'interface to set outbound option.'],
		['p', '=' 				, 'protocol option.'],
		['s', '=' 				, 'source_ip option.'],
		['', 'sport=ARG'		, 'source_port option.'],
		['d', '=' 				, 'destination_ip option.'],
		['', 'dport=ARG'		, 'destination_port option.'],
		['', 'tcp-flags=ARG'	, 'TCP flag option.'],
		['j', '=' 				, 'action option.']
		]).bindHelp();


function acl_parser ( line, lineCount, callback ) {
	let ruleData = {},
		err,
		splitLine = line.trim().split(' ');

	if ( !check_iptables_command(splitLine, lineCount, callback ) ) { return; }
	// console.log(`\n[${lineCount}] [${splitLine}]`);
	
	splitLineOption = Getopt.parse(splitLine);
	// console.info( splitLineOption );

	// manipulate type analysis
	if ( splitLineOption['options']['A'] )
		ruleData['manipulate_type'] = 'append';
	else if ( splitLineOption['options']['I'] )
		ruleData['manipulate_type'] = 'insert';

	// inbound/outbound analysis
	ruleData['in_out'] = splitLineOption['options']['A'] || splitLineOption['options']['I'];
	switch ( ruleData['in_out'] ) {
		case 'INPUT':
			if ( splitLineOption['options']['o'] ) {
				err = `\x1b[1m[acl-input] Line [${lineCount}] syntax error, INPUT chain but \'-o\'.\nData:[${line}]\x1b[0m`;
				callback(err);
				return;
			}
			if ( splitLineOption['options']['i'] ) 
				ruleData['interface'] = splitLineOption['options']['i'];
			break;
		case 'OUTPUT' :
			if ( splitLineOption['options']['i'] ) {
				err = `\x1b[1m[acl-input] Line [${lineCount}] syntax error, OUTPUT chain but \'-i\'.\nData:[${line}]\x1b[0m`;
				callback(err);
				return;
			}
			if ( splitLineOption['options']['o'] ) 
				ruleData['interface'] = splitLineOption['options']['o'];
			break;
	};

	// protocol analysis
	if ( splitLineOption['options']['tcp-flags'] )
		ruleData['protocol'] = 'tcp';
	else if ( splitLineOption['options']['p'] )
		splitLineOption['options']['p'];
	else
		ruleData['protocol'] = 'ip';


	// ip fillin
	let s_ip, d_ip;
	if ( !splitLineOption['options']['s'] )
		s_ip = '0.0.0.0/0';
	else {
		if ( !isValidIPAddr_v4(splitLineOption['options']['s'], lineCount, callback) )
			return;
		s_ip = splitLineOption['options']['s'];
	}
	if ( !splitLineOption['options']['d'] )
		d_ip = '0.0.0.0/0';
	else{
		if ( !isValidIPAddr_v4(splitLineOption['options']['d'], lineCount, callback) )
			return;
		d_ip = splitLineOption['options']['d'];
	}
	ruleData['source_ip'] = ip_data_process( s_ip );
	ruleData['destination_ip'] = ip_data_process( d_ip );


	// tcp flag fill in
	if ( splitLineOption['options']['tcp-flags'] )
		ruleData['tcp_flag'] = splitLineOption['argv'][1].trim().split(',');
	else 
		ruleData['tcp_flag'] = null;

	if ( !splitLineOption['options']['j'] ) {
		err = `\x1b[1m[acl-input] Line [${lineCount}] syntax error, OUTPUT chain but \'-i\'.\nData:[${line}]\x1b[0m`;
		callback(err);
		return;
	}
	ruleData['action'] = splitLineOption['options']['j'];

	callback(null, ruleData);
};


function check_iptables_command ( splitLine, lineCount, callback ) {
	//	need to process \r\n, \n
	let currentOffset = splitLine.indexOf('iptables'),
		err;
	if ( currentOffset == -1 ) {
		err = `\x1b[1m[check_iptables_command] Line [${lineCount}] cannot find "iptables" in the line.\x1b[0m`;
		callback(err);
		return false;
	}
	return true;
};

function isValidIPAddr_v4 ( ipData, lineCount, callback ) {
	let err,
		ipDataSplit = ipData.trim().split('/'),
		ipValidate = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipDataSplit[0]);

	if ( !ipValidate ) {
		err = `\x1b[1m[isValidIPAddr_v4] IP of line [${lineCount}] is invalid.\nData:[${ipDataSplit[0]}]\x1b[0m`;
		callback(err);
		return false;
	}
	else if ( ipDataSplit[1] < 0 || ipDataSplit[1] > 32 ) {
		err = `\x1b[1m[isValidIPAddr_v4] Mask of Line [${lineCount}] is invalid. Data = [${ipDataSplit[1]}]\x1b[0m`;
		callback(err);
		return false;
	}
	else
    	return true;
};

function ip_data_process ( ipData ) {
	const WILDCARD = Math.pow(2, 32) - 1;
	let __param__ = {},
		ipinfo = {
		'ipAddr': ipData.trim().split('/')[0],
		'mask': ipData.trim().split('/')[1],
		__param__ : __param__
	};
	__param__['mask'] = ip_converter( WILDCARD << ( 32 - ipinfo['mask'] ) >>> 0 );
	__param__['wildcard'] = ip_converter( ( WILDCARD >>> ipinfo['mask'] ) >>> 0 );

	__param__['networkAddrValue'] = ( ip_converter(ipinfo['ipAddr']) & ( WILDCARD << ( 32 - ipinfo['mask'] ) ) ) >>> 0 ;
	__param__['networkAddr'] = ip_converter(__param__['networkAddrValue']);
	__param__['boardcastAddrValue'] = ( ip_converter(ipinfo['ipAddr']) | ( WILDCARD >>> ipinfo['mask'] ) ) >>> 0 ;
	__param__['boardcastAddr'] = ip_converter(__param__['boardcastAddrValue']);
	
	// console.log( ipinfo );
	return ipinfo;
};


function ip_converter ( ipData ) {
	if ( !isNaN(ipData) ) {
		let Quotient = [],
			Remainder = [];

		Quotient[0] = ipData;
		for (var i = 0; i < 4; i++) {
			Remainder[i] = Math.floor( Quotient[i] % 256 );
			Quotient[i+1] = Math.floor( Quotient[i] / 256 );
		}

		let mask = Remainder[3];
		for (var i = 2; i >= 0; i--)
			mask = mask + '.' + Remainder[i];
		return mask;
	}
	else {
		let ipSplit = ipData.trim().split('.');
		return ( ( ((+ipSplit[0]) * 256) + (+ipSplit[1]) ) * 256 + (+ipSplit[2]) ) * 256 + (+ipSplit[3]);
	}
};



module.exports.acl_parser = acl_parser;