const util = require('util');
const deepcopy = require('deepcopy');

let IntegrityRule = function ( rule ) {
	return {
		'mode': rule['mode'],
		'interface': rule['interface'],
		'in_out': rule['in_out'],
		'order': rule['order'],
		'flag': rule['tcp_flag'],
		'action': rule['action'],
	};
};

let IntegrityForm = function () {
	return {
		'normal': [],
		'exchanged': []
	};
};

let InterfaceForm = function () {
	return {
		'flag': false,
		'SYN': [],
		'SYN+ACK': [],
		'ACK': [],
		'FIN': [],
		'FIN+ACK': [],
		'RST': []
	};
}

function start ( originalRuleList, ruleGroupList ) {
	// console.log(`\nruleGroupList:\n` + util.inspect( ruleGroupList[0], { showHidden: false, depth:null } ));
	let integrityGroupList = rule_group_list_convert(ruleGroupList);
	console.log(`\nintegrityGroupList:\n` + util.inspect( integrityGroupList[0], { showHidden: false, depth:null } ));

	let integrityForm;
	for (let i=0; i<integrityGroupList.length; i++) {
		console.log(`\nintegrityGroupList[${i}]:\n` + util.inspect( integrityGroupList[i], { showHidden: false, depth:null } ));
		for (let j=0; j<integrityGroupList[i].length; j++) {
			integrityForm = insert_rule_into_form( integrityGroupList[i][j], integrityForm );
		}
		console.log(`\nintegrityForm:\n` + util.inspect( integrityForm, { showHidden: false, depth:null } ));
	}
	
	// console.log(`\n[check_data]:\n` + util.inspect( integrityForm['normal'][0], { showHidden: false, depth:null } ));

};

function rule_group_list_convert ( ruleGroupList ) {
	let newGroupList = [];

	for (let i=0; i<ruleGroupList.length; i++) {
		// console.log(`\n` + ruleGroupList[i].length);
		newGroupList[i] = [];
		for (let j=0; j<ruleGroupList[i].length; j++) {
			let integrityRule = new IntegrityRule( ruleGroupList[i][j] );
			// console.log(`\nintegrityRule:\n` + util.inspect( integrityRule, { showHidden: false, depth:null } ));
			newGroupList[i].push( integrityRule );
		}
	}
	// console.log(`\nnewGroupList:\n` + util.inspect( newGroupList, { showHidden: false, depth:null } ));
	return newGroupList;
}

function insert_rule_into_form ( rule, form ) {
	// console.log(`\nrule:\n` + util.inspect( rule, { showHidden: false, depth:null } ));

	if ( form == null )
		form = new IntegrityForm();
	
	
	let interfaceNumber = -1;
	if ( rule['in_out'] == 'INPUT' )
		interfaceNumber = (rule['interface'].split('eth'))[1] * 2;
	else if ( rule['in_out'] == 'OUTPUT' )
		interfaceNumber = ( (rule['interface'].split('eth'))[1] * 2 ) + 1;

	// console.log( '\ninterfaceNumber: ' + interfaceNumber );

	let flagName;
	let ruleInterface = form[rule['mode']][interfaceNumber];
	if ( ruleInterface == null ) {
		ruleInterface = new InterfaceForm();
		// form[rule['mode']][interfaceNumber].push( ruleInterface );
		// console.log ( '\nruleInterface:  ' + util.inspect( ruleInterface, { showHidden: false, depth:null } ) );
	}

	
	if ( rule['flag'] != null ) {
		ruleInterface['flag'] = true;

		if ( rule['flag'].length == 2 ) {
			if ( rule['flag'][0] == 'ACK' ) {
				flagName = rule['flag'][1] + '+' + rule['flag'][0];
			}
			else if ( rule['flag'][1] == 'ACK' ) {
				flagName = rule['flag'][0] + '+' + rule['flag'][1];
			}
		}
		// console.log( '\nflagName: ' + flagName );
		ruleInterface[flagName].push( rule );
	}
	else if ( rule['flag'] == null ) {
		Object.keys(ruleInterface).forEach( (keys) => {
			if ( typeof( ruleInterface[keys] ) != 'boolean' ) {
				ruleInterface[keys].push( rule );
			}
		});
	}
	form[rule['mode']][interfaceNumber] = ruleInterface;

	// console.log(`\nform:\n` + util.inspect( form, { showHidden: false, depth:null } ));
	return form;
}




module.exports.start = start;