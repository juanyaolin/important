
const fs = require('fs');
const path = require('path');
const util = require('util');
const aclParser = require( path.join(__dirname, 'acl-parser.js') );
const ararMain = require( path.join(__dirname, 'arar-main.js') );

let aclData = {};

function acl_import_handler ( filepath ) {
	

	let lineCount = 0,
		lineReader = require('readline').createInterface({
		input: fs.createReadStream(filepath)
	});

	lineReader.on( 'line', function ( line ) {
		// console.log(line);
		lineCount++;
		aclParser.acl_parser(line, lineCount, ( err, ruleData ) => {
			if ( err ) { console.warn(err); return; };
			let interfaces = ruleData['interface'],
				io = ruleData['in_out'];
			aclData[interfaces] = aclData[interfaces] || {};
			aclData[interfaces][io] = aclData[interfaces][io] || [];
			ruleData['order'] = aclData[interfaces][io].length;
			ruleData['mode'] = 'normal';
			aclData[interfaces][io].push(ruleData);
		});
	});
	
	lineReader.on( 'close', () => {
		let aclObject = {},
			ruleList = [];

		aclObject['normal'] = aclData;
		aclObject['exchanged'] = exchange_source_destination_info(aclData);
		ruleList = rule_list_transfer(aclObject);
				
		
		start_time = new Date().getTime();
		
		ararMain.start(ruleList);
		
		
		// /* Clone ruleList test */
		// console.log( `\nruleList[0]:\n` + util.inspect( ruleList[0], { showHidden: false, depth:null } ) );
		// console.log( `\nruleListClone[0]:\n` + util.inspect( ruleList.slice(0, 1), { showHidden: false, depth:null } ) );

		// ruleList[0]['fortest'] = "fortest";
		// console.log( `\nruleList[0]:\n` + util.inspect( ruleList[0], { showHidden: false, depth:null } ) );
		// console.log( `\nruleListClone[0]:\n` + util.inspect( ruleList.slice(0, 1), { showHidden: false, depth:null } ) );

		// console.log( util.inspect( aclObject, { showHidden: false, depth:null } ) );
		// console.log( util.inspect( ruleList, { showHidden: false, depth:null } ) );
		// console.log( ruleList.length );
		


		end_time = new Date().getTime();
		console.log( '\n\n\x1b[1mExcuting time:[ ' + (end_time - start_time) / 1000 + ' sec ]\x1b[0m' );
	});
	
};


function exchange_source_destination_info( aclData )  {
	let tempObject = {},
		tempIPData = {};
	tempObject = JSON.parse( JSON.stringify(aclData) );

	Object.keys(tempObject).forEach( (first_key) => {
		Object.keys(tempObject[first_key]).forEach( (second_key) => {
			for ( let i = 0; i < tempObject[first_key][second_key].length; i++) {
			tempIPData = JSON.parse( JSON.stringify(tempObject[first_key][second_key][i]['source_ip']) );
			tempObject[first_key][second_key][i]['source_ip'] = tempObject[first_key][second_key][i]['destination_ip'];
			tempObject[first_key][second_key][i]['destination_ip'] = tempIPData;
			tempObject[first_key][second_key][i]['mode'] = 'exchanged';
			};
		});
	});
	return tempObject;
};

function rule_list_transfer ( aclObject ) {
	let ruleList = [];

	Object.keys(aclObject).forEach( (first_key) => {
		Object.keys(aclObject[first_key]).forEach( (second_key) => {
			Object.keys(aclObject[first_key][second_key]).forEach( (thrid_key) => {
				for ( let i = 0; i < aclObject[first_key][second_key][thrid_key].length; i++) 
					ruleList.push( aclObject[first_key][second_key][thrid_key][i] );
			});
		});
	});
	return ruleList;
};


module.exports.acl_import_handler = acl_import_handler;