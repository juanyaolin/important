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

let InterfaceForm = function ( rule ) {
	return {
		'interface': rule['interface'],
		// 'flag': false,
		// 'integrity': true,
		'INPUT': {
			'flag': false,
			'integrity': undefined,
			'SYN': [],
			'SYN+ACK': [],
			'ACK': [],
			'FIN': [],
			'FIN+ACK': [],
			'RST': []
		},
		'OUTPUT': {
			'flag': false,
			'integrity': undefined,
			'SYN': [],
			'SYN+ACK': [],
			'ACK': [],
			'FIN': [],
			'FIN+ACK': [],
			'RST': []
		}
	};
};


function start ( originalRuleList, ruleGroupList ) {
	// console.log(`\nruleGroupList:\n` + util.inspect( ruleGroupList[0], { showHidden: false, depth:null } ));
	let integrityGroupList = rule_group_list_convert(ruleGroupList);
	let alarm, alarmEntry = [];
	// console.log(`\nintegrityGroupList:\n` + util.inspect( integrityGroupList, { showHidden: false, depth:null } ));
	
	for (let i=0; i<integrityGroupList.length; i++) {
		// console.log(`\nintegrityGroupList[${i}]:\n` + util.inspect( integrityGroupList[i], { showHidden: false, depth:null } ));
		let integrityForm, anomalyInspectForm = [];
		alarmEntry[i] = []
		for (let j=0; j<integrityGroupList[i].length; j++) {
			integrityForm = insert_rule_into_form( integrityGroupList[i][j], integrityForm );
		}

		for (let j=0; j<integrityForm['normal'].length; j++) {
			let currentInterface = integrityForm['normal'][j];
			Object.keys(currentInterface).forEach((keys) => {
				if ( currentInterface[keys]['flag'] == true ) {
					if ( currentInterface[keys]['integrity'] == true ) {
						// do only on the inbound/outbound of interfaces which with flag and integrity
						let integrityCheck = ckeck_integrity_of_form(integrityForm, anomalyInspectForm, j, keys, (alarm) => {
							alarmEntry[i].push(alarm);
						});
						if ( integrityCheck == true ) {
							let anomalyCheck = check_anomaly(anomalyInspectForm, (alarm) => {
								alarmEntry[i].push(alarm);
							});
							// console.log( 'check is pass' );
							// console.log(`\nanomalyInspectForm:\n` + util.inspect( anomalyInspectForm, { showHidden: false, depth:null } ));
						}
						// console.log(`\nhave flag:\n` + util.inspect( currentInterface[keys], { showHidden: false, depth:null } ));
					}
					else {
						alarm = `[eth${j}-${keys}] has rule with special flag, but not integrity.`;
						alarmEntry[i].push(alarm);
					}
				}
			});
		}
		/*
		// integrityForm have done, next step.
		for (let j=0; j<integrityForm['normal'].length; j++) {
			let currentInterface = integrityForm['normal'][j];
			if ( currentInterface != null ) {
				// console.log( currentInterface['integrity'] + '\t'+ currentInterface['flag'] );
				if ( currentInterface['flag'] == true ) {
					let test = check_integrity_of_form(integrityForm, anomalyInspectForm, j, (alarm) => {
						alarmEntry[i].push(alarm);
					} );
					console.log('Is this form integrity?  Ans:' + test );

				}
				else {
					// this interface without spectify flag
					continue;
				}
				
			}
			else {
				// this interface is null
				continue;
			}
		}
		// get_flag_interface_form( integrityForm );
		*/
		// console.log(`\nanomalyInspectForm:\n` + util.inspect( anomalyInspectForm, { showHidden: false, depth:null } ));
		// console.log(`\nintegrityForm:\n` + util.inspect( integrityForm, { showHidden: false, depth:null } ));
	}
	console.log(`\nalarmEntry:\n` + util.inspect( alarmEntry, { showHidden: false, depth:null } ));

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
	
	let interfaceNumber = (rule['interface'].split('eth'))[1];
	if ( form[rule['mode']][interfaceNumber] == null )
		form[rule['mode']][interfaceNumber] = new InterfaceForm( rule );

	let currentInterface = form[rule['mode']][interfaceNumber];
	let currentBound = currentInterface[rule['in_out']];

	if ( rule['flag'] != null ) {
		// rule with specify flag
		currentBound['flag'] = true;

		let flagName;
		if ( rule['flag'].length == 2 ) {
			if ( rule['flag'][0] == 'ACK' ) {
				flagName = rule['flag'][1] + '+' + rule['flag'][0];
			}
			else if ( rule['flag'][1] == 'ACK' ) {
				flagName = rule['flag'][0] + '+' + rule['flag'][1];
			}
		}
		currentBound[flagName].push( rule );
	}
	else if ( rule['flag'] == null ) {
		// rule without specify flag
		Object.keys(currentBound).forEach( (keys) => {
			if ( (typeof( currentBound[keys] ) !== "boolean") && (typeof(currentBound[keys]) !== "undefined") ) {
				currentBound[keys].push( rule );
			}
		});
	}

	// check that is it integrity of interface
	let boundIntegrity = 0;
	Object.keys(currentBound).forEach( (keys) => {
		if ( (typeof( currentBound[keys] ) !== "boolean") && (typeof(currentBound[keys]) !== "undefined") ) {
			// console.log(`currentBound[${keys}] = ${typeof(currentBound[keys])}`);

			if ( typeof(currentBound[keys]) === 'undefined' )
				console.log('it\'s undefined\n' + typeof(currentBound[keys]));

			if ( currentBound[keys].length == 0 ) {
				currentBound['integrity'] = false;
			}
			if ( currentBound[keys].length > 0 ) {
				boundIntegrity++;
			}
		}
	});
	if ( boundIntegrity == 6 ) {
		currentBound['integrity'] = true;
	}
	
	// console.log(`\nform:\n` + util.inspect( form, { showHidden: false, depth:null } ));
	return form;
}

function ckeck_integrity_of_form ( form, newForm, interface, in_out, callback ) {
	let alarm,
		fulls = 0;

	for (let i=0; i<form['normal'].length; i++) {
		let insertInterface = {
			// 'flag': false,
			'integrity': undefined,
			'INPUT': undefined,
			'OUTPUT': undefined
		};

		if ( form['normal'][i] != null ) {
			if ( i == interface ) {
				if ( in_out == 'INPUT' ) {
					if ( (form['normal'][i]['INPUT'] == null) || (form['normal'][i]['INPUT']['integrity'] == false) || (form['normal'][i]['INPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] N-eth${i}-INPUT is null or not integrity.`;
						callback(alarm);
					}
					else if ( (form['exchanged'][i]['OUTPUT'] == null) || (form['exchanged'][i]['OUTPUT']['integrity'] == false) || (form['exchanged'][i]['OUTPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] E-eth${i}-OUTPUT is null or not integrity.`;
						callback(alarm);
					}
					else {
						insertInterface['INPUT'] = form['normal'][i]['INPUT'];
						insertInterface['OUTPUT'] = form['exchanged'][i]['OUTPUT'];
						if ( (insertInterface['INPUT']['integrity'] == true) && (insertInterface['OUTPUT']['integrity'] == true) )
							insertInterface['integrity'] = true;
						else
							insertInterface['integrity'] = false;
						fulls++;
					}
				}
				else if ( in_out == 'OUTPUT' ) {
					if ( (form['exchanged'][i]['INPUT'] == null) || (form['exchanged'][i]['INPUT']['integrity'] == false) || (form['exchanged'][i]['INPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] E-eth${i}-INPUT is null or not integrity.`;
						callback(alarm);
					}
					else if ( (form['normal'][i]['OUTPUT'] == null) || (form['normal'][i]['OUTPUT']['integrity'] == false) || (form['normal'][i]['OUTPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] N-eth${i}-OUTPUT is null or not integrity.`;
						callback(alarm);
					}
					else {
						insertInterface['INPUT'] = form['exchanged'][i]['INPUT'];
						insertInterface['OUTPUT'] = form['normal'][i]['OUTPUT'];
						if ( (insertInterface['INPUT']['integrity'] == true) && (insertInterface['OUTPUT']['integrity'] == true) )
							insertInterface['integrity'] = true;
						else
							insertInterface['integrity'] = false;
						fulls++;
					}
				}
			}
			else if ( i != interface ) {


				if ( in_out == 'INPUT' ) {
					if ( (form['exchanged'][i]['INPUT'] == null) || (form['exchanged'][i]['INPUT']['integrity'] == false) || (form['exchanged'][i]['INPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] E-eth${i}-INPUT is null or not integrity.`;
						callback(alarm);
					}
					else if ( (form['normal'][i]['OUTPUT'] == null) || (form['normal'][i]['OUTPUT']['integrity'] == false) || (form['normal'][i]['OUTPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] N-eth${i}-OUTPUT is null or not integrity.`;
						callback(alarm);
					}
					else {
						insertInterface['INPUT'] = form['exchanged'][i]['INPUT'];
						insertInterface['OUTPUT'] = form['normal'][i]['OUTPUT'];
						if ( (insertInterface['INPUT']['integrity'] == true) && (insertInterface['OUTPUT']['integrity'] == true) )
							insertInterface['integrity'] = true;
						else
							insertInterface['integrity'] = false;
						fulls++;
					}
				}
				else if ( in_out == 'OUTPUT' ) {
					if ( (form['normal'][i]['INPUT'] == null) || (form['normal'][i]['INPUT']['integrity'] == false) || (form['normal'][i]['INPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] N-eth${i}-INPUT is null or not integrity.`;
						callback(alarm);
					}
					else if ( (form['exchanged'][i]['OUTPUT'] == null) || (form['exchanged'][i]['OUTPUT']['integrity'] == false) || (form['exchanged'][i]['OUTPUT']['integrity'] == undefined) ) {
						alarm = `[eth${interface}-${in_out}] E-eth${i}-OUTPUT is null or not integrity.`;
						callback(alarm);
					}
					else {
						insertInterface['INPUT'] = form['normal'][i]['INPUT'];
						insertInterface['OUTPUT'] = form['exchanged'][i]['OUTPUT'];
						if ( (insertInterface['INPUT']['integrity'] == true) && (insertInterface['OUTPUT']['integrity'] == true) )
							insertInterface['integrity'] = true;
						else
							insertInterface['integrity'] = false;
						fulls++;
					}
				}


			}
		}
		newForm.push(insertInterface);
	}
	console.log('fulls = ' + fulls);
	if ( fulls >= 2 )
		return true;
	else{
		alarm = `[eth${interface}-${in_out}] number of integrity interface is less than 2.`;
		callback(alarm);
		return false;
	}
}

function check_anomaly ( form, callback ) {
	console.log(`\nform:\n` + util.inspect( form, { showHidden: false, depth:null } ));


	for (let i=0; i<form.length; i++) {
		Object.keys(form[i]).forEach((keys) => {
			

			if ( (form[i][keys]['flag'] == true) && (form[i][keys]['SYN'][0]['mode'] == 'normal') ) {
				let synCase = 0, synInterface = [],
					finCase = 0, finInterface = [],
					rstCase = 0, rstInterface = [],
					alarm = null;


				console.log('the right interface\n' + i + '\t' + keys);
				// let currentBound = form[i][keys];
				if ( form[i]['INPUT']['SYN'][0]['action'] == 'ACCEPT' ) {
					synInterface.push('INPUT');
					synCase++;
				}
				if ( form[i]['OUTPUT']['SYN'][0]['action'] == 'ACCEPT' ) {
					synInterface.push('OUTPUT');
					synCase++;
				}

				console.log('synCase = ' + synCase);
				console.log('synInterface = ' + synInterface);
				switch ( synCase ) {
					case 0:
						for (let x=0; x<form.length; x++) {
							Object.keys(form[x]).forEach((firstKey) => {
								Object.keys(form[x][firstKey]).forEach((secondKey) => {
									if ( typeof(form[x][firstKey][secondKey]) !== 'boolean' ) {
										if ( form[x][firstKey][secondKey][0]['action'] != 'DENY' ){
											alarm = `[eth${i}-${firstKey}] action of ${secondKey} is not DENY.`
											callback(alarm);
										}
									}
								});
							});
						}
						break;




					case 1:
						
						break;





					case 2:
						// Checking SYN series
						if ( form[i]['INPUT']['SYN+ACK'][0]['action'] != 'ACCEPT' ) {
							alarm = `[eth${i}-INPUT] flag SYN+ACK is not ACCEPT.`
							callback(alarm);
						}
						if ( form[i]['INPUT']['ACK'][0]['action'] != 'ACCEPT' ) {
							alarm = `[eth${i}-INPUT] flag ACK is nt ACCEPT.`
							callback(alarm);
						}
						if ( form[i]['OUTPUT']['SYN+ACK'][0]['action'] != 'ACCEPT' ) {
							alarm = `[eth${i}-OUTPUT] flag SYN+ACK is not ACCEPT.`
							callback(alarm);
						}
						if ( form[i]['OUTPUT']['ACK'][0]['action'] != 'ACCEPT' ) {
							alarm = `[eth${i}-OUTPUT] flag ACK is not ACCEPT.`
							callback(alarm);
						}
						
						// checking FIN series
						if ( form[i]['INPUT']['FIN'][0]['action'] == 'ACCEPT' ) {
							if ( form[i]['OUTPUT']['FIN+ACK'][0]['action'] == 'ACCEPT' ) {
								finInterface.push('INPUT');
								finCase++;
							}
							else if ( form[i]['OUTPUT']['FIN+ACK'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${i}] FIN of INPUT is ACCEPT, but FIN+ACK of OUTPUT is DENY.`
								callback(alarm);
							}
						}
						if ( form[i]['OUTPUT']['FIN'][0]['action'] == 'ACCEPT' ) {
							if ( form[i]['INPUT']['FIN+ACK'][0]['action'] == 'ACCEPT' ) {
								finInterface.push('OUTPUT');
								finCase++;
							}
							else if ( form[i]['INPUT']['FIN+ACK'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${i}] FIN of OUTPUT is ACCEPT, but FIN+ACK of INPUT is DENY.`
								callback(alarm);
							}
						}
						if ( finCase == 0 ){
							alarm = `[eth${i}] both INPUT and OUTPUT cannot pass FIN series flag correctly.`
							callback(alarm);
						}

						// checking RST series
						if ( form[i]['INPUT']['RST'][0]['action'] == 'ACCEPT' ) {
							rstInterface.push('INPUT');
							rstCase++;
						}
						if ( form[i]['OUTPUT']['RST'][0]['action'] == 'ACCEPT' ) {
							rstInterface.push('OUTPUT');
							rstCase++;
						}
						if ( rstCase == 0 ) {
							alarm = `[eth${i}] both INPUT and OUTPUT cannot pass RST flag.`
							callback(alarm);
						}

						console.log('finInterface = ' + finInterface);
						console.log('rstInterface = ' + rstInterface);
						if ( alarm != null ) {
							alarm = `[eth${i}] some warning is occured on current interface, please check information above.`
							callback(alarm);
							break;
						}


						// checking another interface
						for (let x=0; x<form.length; x++) {
							if ( x == i )
								continue;

							// checking SYN series 
							if ( form[x]['INPUT']['SYN'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${x}-INPUT] flag SYN is not ACCEPT.`
								callback(alarm);
							}
							if ( form[i]['INPUT']['SYN+ACK'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${i}-INPUT] flag SYN+ACK is not ACCEPT.`
								callback(alarm);
							}
							if ( form[i]['INPUT']['ACK'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${i}-INPUT] flag ACK is nt ACCEPT.`
								callback(alarm);
							}
							if ( form[x]['OUTPUT']['SYN'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${x}-OUTPUT] flag SYN is not ACCEPT.`
								callback(alarm);
							}
							if ( form[i]['OUTPUT']['SYN+ACK'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${i}-OUTPUT] flag SYN+ACK is not ACCEPT.`
								callback(alarm);
							}
							if ( form[i]['OUTPUT']['ACK'][0]['action'] != 'ACCEPT' ) {
								alarm = `[eth${i}-OUTPUT] flag ACK is not ACCEPT.`
								callback(alarm);
							}

							// checking FIN series
							for (let m=0; m<finInterface.length; m++) {
								if ( finInterface[m] == 'INPUT' ) {
									if ( (form[x]['INPUT']['FIN'][0]['action'] != 'ACCEPT') || (form[x]['OUTPUT']['FIN+ACK'][0]['action'] != 'ACCEPT') ) {
										alarm = `[eth${x}] FIN of INPUT or FIN+ACK of OUTPUT is not ACCEPT.`;
										callback(alarm);
									}
								}
								else if ( finInterface[m] == 'OUTPUT' ) {
									if ( (form[x]['OUTPUT']['FIN'][0]['action'] != 'ACCEPT') || (form[x]['INPUT']['FIN+ACK'][0]['action'] != 'ACCEPT') ) {
										alarm = `[eth${x}] FIN of OUTPUT or FIN+ACK of INPUT is not ACCEPT.`;
										callback(alarm);
									}
								}
							}

							for (let m=0; m<finInterface.length; m++) {
								if ( form[x][finInterface[m]]['FIN'][0]['action'] != 'ACCEPT' ){
									alarm = `[eth${x}] FIN of OUTPUT or FIN+ACK of INPUT is not ACCEPT.`;
									callback(alarm);
								}
							}
						}

						break;



					default:
						alarm = `[eth${i}] unexpect synCase occur, synCase = ${synCase}.`;
						callback(alarm);
						break;
				}





			}
		});
	}

}

/* check_fin_and_rst_series ()
 * [return]
 * true: fin and rst is correct
 * false: fin or rst is not correct
 */
function check_fin_and_rst_series ( form, interfaceNumber, in_out, callback ) {
	let finCase = 0,
		rstCase = 0,
		alarm = null;

	// FIN series checking
	if ( form[interfaceNumber]['INPUT']['FIN'][0]['action'] == 'ACCEPT' ) {
		if ( form[interfaceNumber]['OUTPUT']['FIN+ACK'][0]['action'] == 'ACCEPT' ) {
			finCase++;
		}
		else if ( form[interfaceNumber]['OUTPUT']['FIN+ACK'][0]['action'] != 'ACCEPT' ) {
			alarm = `[eth${interfaceNumber}] FIN of INPUT is ACCEPT, but FIN+ACK of OUTPUT is DENY.`
			callback(alarm);
		}
	}
	if ( form[interfaceNumber]['OUTPUT']['FIN'][0]['action'] == 'ACCEPT' ) {
		if ( form[interfaceNumber]['INPUT']['FIN+ACK'][0]['action'] == 'ACCEPT' ) {
			finCase++;
		}
		else if ( form[interfaceNumber]['INPUT']['FIN+ACK'][0]['action'] != 'ACCEPT' ) {
			alarm = `[eth${interfaceNumber}] FIN of OUTPUT is ACCEPT, but FIN+ACK of INPUT is DENY.`
			callback(alarm);
		}
	}
	if ( finCase == 0 ){
		alarm = `[eth${interfaceNumber}] both INPUT and OUTPUT cannot pass FIN series flag correctly.`
		callback(alarm);
		return false;
	}

	// RST series checking
	if ( form[interfaceNumber]['INPUT']['RST'][0]['action'] == 'ACCEPT' )
		rstCase++;
	if ( form[interfaceNumber]['OUTPUT']['RST'][0]['action'] == 'ACCEPT' )
		rstCase++;
	if ( rstCase == 0 ) {
		alarm = `[eth${interfaceNumber}] both INPUT and OUTPUT cannot pass RST flag.`
		callback(alarm);
		return false;
	}

	if ( alarm == null ){
		return true;
	}
	else {
		alarm = `[eth${interfaceNumber}] some warning is occured, please check information above.`
		callback(alarm);
		return false;
	}
}

/* check_integrity_of_form ()
 * [return]
 * true: form is integrity
 * false: form isn't integrity
 */
 /*
function check_integrity_of_form ( form, newForm, interfaceNumber, callback ) {
	// let newForm = [];
	let normal = form['normal'];
	let exchanged = form['exchanged'];
	let alarm,
		isAlarm = true;

	if ( (interfaceNumber%2) == 0 ) {
		// for interfaceNumber is even
		for (let i=0; i<form['normal'].length; i++) {
			if ( (i%2) == 0 ) {
				if ( i == interfaceNumber ){
					if ( (normal[i] == null) || (normal[i]['integrity'] == false) ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(normal[i]);
				}
				else {
					if ( exchanged[i] == null ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(exchanged[i]);
				}
			}
			else if ( (i%2) == 1 ) {
				if ( i == (interfaceNumber+1) ) {
					if ( exchanged[i] == null ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(exchanged[i]);
				}
				else {
					if ( (normal[i] == null) || (normal[i]['integrity'] == false) ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(normal[i]);
				}
			}
		}
	}
	else if ( (interfaceNumber%2) == 1 ) {
		// for interfaceNumber is odd
		for (let i=0; i<form['normal'].length; i++) {
			if ( (i%2) == 0 ) {
				if ( i == (interfaceNumber-1) ){
					if ( exchanged[i] == null ) {
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(exchanged[i]);
				}
				else {
					if ( (normal[i] == null) || (normal[i]['integrity'] == false) ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(normal[i]);
				}
			}
			else if ( (i%2) == 1 ) {
				if ( i == interfaceNumber ) {
					if ( (normal[i] == null) || (normal[i]['integrity'] == false) ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(normal[i]);
				}
				else {
					if ( exchanged[i] == null ){
						alarm = `InterfaceNumber[${i}] is null, when checking integrity of interfaceNumber[${interfaceNumber}]`;
						callback(alarm);
						isAlarm = false;
						continue;
					}
					else
						newForm.push(exchanged[i]);
				}
			}
		}
	}
	// console.log(`\nnewForm:\n` + util.inspect( newForm, { showHidden: false, depth:null } ));
	return isAlarm;
}
*/

module.exports.start = start;