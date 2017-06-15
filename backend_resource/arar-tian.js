const util = require('util');
const deepcopy = require('deepcopy');
const myutils = require('./my-utils');

let count = 0;

let ARARNode = function () {
	/*	ARARNode{}
	 *	
	 *	[TCP-Flag]
	 *	false:	rule in nodeRules without TCP-flag
	 *	true:	rule in nodeRules with TCP-flag
	 */
	count++;
	return {
		'RSA_Source': undefined,
		'RSA_Destination': undefined,
		'nodeLevel': undefined,
		'nodeZero': undefined,
		'nodeOne': undefined,
		'nodeRules': []
	};
};

let ARARParameter = function () {
	return {
		'RSA_Source': undefined,
		'RSA_Destination': undefined,
		'tempRSA_Source': undefined,
		'tempRSA_Destination': undefined,
		'Max_Source': undefined,
		'Max_Destination': undefined,
		'nodeLevel': undefined,
		'ruleCoordinate': [],
		'cuttingCoordinate': []
	};
};

let TempRule = function () {
	/*	tempRule{}
	 *	
	 *	[difference]
	 *	false:	same block
	 *	true:	different block
	 */
	return {
		'value1': undefined,
		'value2': undefined,
		'value3': undefined,
		'value4': undefined,
		'block1': undefined,
		'block2': undefined,
		'difference': undefined,
	};
};

let ARARRule = function () {
	return {
		'order': undefined,
		'max_sip': undefined,
		'min_sip': undefined,
		'max_dip': undefined,
		'min_dip': undefined,
		'cuttingCoordinate': []
	};
};



function start ( ruleList ) {
	let parameter = looking_for_region_segmentation_value(ruleList);
	let newRuleList = rule_list_convert(ruleList);
	let ARARTree;
	ARARTree = arar_create( newRuleList, parameter );
};

/*	segmentation()
 *
 *	[mode]
 *	false:	source
 * 	true:	destination
 *
 *	[isFirst]
 *	false:	not first
 *	true:	first
 */
function segmentation ( rule, parameter, mode, isFirst ) {
	let tempRule = new TempRule();

	if ( !mode ) {
		if ( isFirst ) {
			tempRule['value1'] = rule['min_sip'];
			tempRule['value2'] = rule['max_sip'];
			tempRule['block1'] = Math.floor( tempRule['value1'] / parameter['RSA_Source'] );
			tempRule['block2'] = Math.floor( tempRule['value2'] / parameter['RSA_Source'] );
		}
		else {
			tempRule['value1'] = rule['cuttingCoordinate'][0];
			tempRule['value2'] = rule['cuttingCoordinate'][1];
			tempRule['block1'] = Math.floor( tempRule['value1'] / parameter['RSA_Source'] );
			tempRule['block2'] = Math.floor( tempRule['value2'] / parameter['RSA_Source'] );
		}
	}

	if ( mode ) {
		if ( isFirst ) {
			tempRule['value1'] = rule['min_dip'];
			tempRule['value2'] = rule['max_dip'];
			tempRule['block1'] = Math.floor( tempRule['value1'] / parameter['RSA_Destination'] );
			tempRule['block2'] = Math.floor( tempRule['value2'] / parameter['RSA_Destination'] );
		}
		else {
			tempRule['value1'] = rule['cuttingCoordinate'][0];
			tempRule['value2'] = rule['cuttingCoordinate'][1];
			tempRule['block1'] = Math.floor( tempRule['value1'] / parameter['RSA_Source'] );
			tempRule['block2'] = Math.floor( tempRule['value2'] / parameter['RSA_Source'] );
		}
	}

	if ( tempRule['block2'] == 2 )
		tempRule['block2'] = 1;

	if ( tempRule['block1'] == tempRule['block2'] ) {
		tempRule['value3'] = 0;
		tempRule['value4'] = 0;
		tempRule['difference'] = false;
	}
	else if ( tempRule['block1'] != tempRule['block2'] )
	{
		if ( !mode ) {
			tempRule['difference'] = true;
			if ( tempRule['value2'] == parameter['RSA_Source'] )
				tempRule['difference'] = false;
			tempRule['value4'] = tempRule['value2'];
			tempRule['value2'] = parameter['RSA_Source'];
			tempRule['value3'] = tempRule['value2'];
		}
		else if ( mode ) {
			tempRule['difference'] = true;
			if ( tempRule['value2'] == parameter['RSA_Destination'] )
				tempRule['difference'] = false;
			tempRule['value4'] = tempRule['value2'];
			tempRule['value2'] = parameter['RSA_Destination'];
			tempRule['value3'] = tempRule['value2'];
		}
	}

	return tempRule;
};


/*	insert()
 *
 *	[mode]
 *	false:	source
 * 	true:	destination
 */
function insert ( node, calRule, rule, parameter, mode ) {
	let insertRule = deepcopy(rule);
	insertRule['cuttingCoordinate'] = [];
	insertRule['cuttingCoordinate'][0] = calRule['value1'];
	insertRule['cuttingCoordinate'][1] = calRule['value2'];


	if ( node == null ){
		//	First rule
	
		let newNode = new ARARNode();
		newNode['nodeRules'].push(insertRule);
		newNode['RSA_Source'] = parameter['RSA_Source'];
		newNode['RSA_Destination'] = parameter['RSA_Destination'];
		newNode['nodeLevel'] = parameter['nodeLevel'];

		node = new ARARNode();
		node['RSA_Source'] = parameter['RSA_Source'];
		node['RSA_Destination'] = parameter['RSA_Destination'];
		node['nodeLevel'] = parameter['nodeLevel'];

		if ( !mode ) {
			if ( calRule['value1'] < parameter['RSA_Source'] ) {
				node['nodeZero'] = deepcopy(newNode);
			}
			else {
				node['nodeOne'] = deepcopy(newNode);
			}
		}
		else if ( mode ) {
			if ( calRule['value1'] < parameter['RSA_Destination'] ) {
				node['nodeZero'] = deepcopy(newNode);
			}
			else {
				node['nodeOne'] = deepcopy(newNode);
			}
		}
	}
	else {	
	//	Follow rules
	
		if ( ( (!mode) && (calRule['value1']<parameter['RSA_Source']) ) || ( (mode) && (calRule['value1']<parameter['RSA_Destination']) ) ) {
			//	nodeZero
			
			if ( node['nodeZero'] == null ) {
				//	no nodes

				let newNode = new ARARNode();
				newNode['nodeRules'].push(insertRule);
				newNode['RSA_Source'] = parameter['RSA_Source'];
				newNode['RSA_Destination'] = parameter['RSA_Destination'];
				newNode['nodeLevel'] = parameter['nodeLevel'];
				node['nodeZero'] = deepcopy(newNode);
			}
			else {
				//	has nodes

				if ( node['nodeZero']['nodeRules'].length == 0 ) {
					//	has other nodes

					let tempParameter = deepcopy(parameter);
					tempParameter['nodeLevel'] = node['nodeZero']['nodeLevel'];
					tempParameter['RSA_Source'] = node['nodeZero']['RSA_Source'];
					tempParameter['RSA_Destination'] = node['nodeZero']['RSA_Destination'];

					node['nodeZero']['nodeRules'].push(insertRule);
					node['nodeZero'] = add_structure(node['nodeZero'], tempParameter, mode);
				}
				else {
					//	has other rules

					node['nodeZero']['nodeRules'].push(insertRule);
					if ( check_rule_range_is_same(node['nodeZero']['nodeRules']) ) {
						let updateParameter = deepcopy(parameter);
						updateParameter = update_region_segmentation_value(node['nodeZero']['nodeRules'][0], updateParameter, mode);
						node['nodeZero'] = restructure(node['nodeZero'], updateParameter, mode);
						node['nodeZero']['nodeRules'] = [];
					}
				}
			}
		}
		else if ( ( (!mode) && (calRule['value1']>=parameter['RSA_Source']) ) || ( (mode) && (calRule['value1']>=parameter['RSA_Destination']) ) ) {
			//	nodeOne

			if ( node['nodeOne'] == null ) {
				//	no nodes

				let newNode = new ARARNode();
				newNode['nodeRules'].push(insertRule);
				newNode['RSA_Source'] = parameter['RSA_Source'];
				newNode['RSA_Destination'] = parameter['RSA_Destination'];
				newNode['nodeLevel'] = parameter['nodeLevel'];
				node['nodeOne'] = deepcopy(newNode);
			}
			else {
				//	has nodes

				if ( node['nodeOne']['nodeRules'].length == 0 ) {
					//	has other nodes

					let tempParameter = deepcopy(parameter);
					tempParameter['nodeLevel'] = node['nodeOne']['nodeLevel'];
					tempParameter['RSA_Source'] = node['nodeOne']['RSA_Source'];
					tempParameter['RSA_Destination'] = node['nodeOne']['RSA_Destination'];

					node['nodeOne']['nodeRules'].push(insertRule);
					node['nodeOne'] = add_structure(node['nodeOne'], tempParameter, mode);
				}
				else {
					//	has other rules

					node['nodeOne']['nodeRules'].push(insertRule);
					if ( check_rule_range_is_same(node['nodeOne']['nodeRules']) ) {
						let updateParameter = deepcopy(parameter);
						updateParameter = update_region_segmentation_value(node['nodeOne']['nodeRules'][0], updateParameter, mode);
						node['nodeOne'] = restructure(node['nodeOne'], updateParameter, mode);
						node['nodeOne']['nodeRules'] = [];
					}
				}
			}
		}
	}
	// console.log(`\nnewNode:\n` + util.inspect( newNode, { showHidden: false, depth:null } ));
	// console.log(`\ninsertRule:\n` + util.inspect( insertRule, { showHidden: false, depth:null } ));
	// console.log(`\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ));
	return node;
};

/*	add_structure()
 *
 *	[mode]
 *	false:	source
 * 	true:	destination
 */
function add_structure ( node, parameter, mode ) {
	let tempRuleList = [];

	for (let i=0; i<node['nodeRules'].length; i++)
		tempRuleList[i] = deepcopy(node['nodeRules'][i]);
	node['nodeRules'] = [];

	let tempRule = segmentation( tempRuleList[0], parameter, mode, false );
	let calRule = deepcopy(tempRule);
	node = insert(node, calRule, tempRuleList[0], parameter, mode);

	if ( tempRule['difference'] == true ) {
		calRule['value1'] = calRule['value3'];
		calRule['value2'] = calRule['value4'];
		node = insert(node, calRule, tempRuleList[0], parameter, mode);
	}

	return node;
};

/*	restructure()
 *
 *	[mode]
 *	false:	source
 * 	true:	destination
 */
function restructure ( node, parameter, mode ) {
	let tempRuleList = [];
	for (let i=0; i<node['nodeRules'].length; i++)
		tempRuleList[i] = deepcopy(node['nodeRules'][i]);
	node = {};

	for (let i=0; i<tempRuleList.length; i++) {
		let tempRule = segmentation(tempRuleList[i], parameter, mode, false);
		let calRule = deepcopy(tempRule);
		node = insert(node, calRule, tempRuleList[i], parameter, mode);

		if ( tempRule['difference'] == true ) {
			calRule['value1'] = calRule['value3'];
			calRule['value2'] = calRule['value4'];
			node = insert(node, calRule, tempRuleList[i], parameter, mode);
		}
	}
	return node;
};

/*	check_rule_range_is_same()
 *
 *	[mode]
 *	false:	source
 * 	true:	destination
 */
function check_rule_range_is_same ( ruleList, mode ) {
	for ( let i=0; i<(ruleList.length-1); i++)
		if ( ( ruleList[i]['cuttingCoordinate'][0] == ruleList[i+1]['cuttingCoordinate'][0] ) || ( ruleList[i]['cuttingCoordinate'][1] == ruleList[i+1]['cuttingCoordinate'][1] ) ) {
			// console.log('same');
			return true;
		}
	// console.log('different');
	return false;
};

/*	update_region_segmentation_value()
 *
 *	[mode]
 *	false:	source
 * 	true:	destination
 */
function update_region_segmentation_value ( rule, parameter, mode ) {
	let newParameter = deepcopy(parameter);

	if ( !mode ){
		// source
		if ( rule['cuttingCoordinate'][0] < newParameter['RSA_Source'] )
			newParameter['RSA_Source'] &= ~( newParameter['tempRSA_Source'] >> ( newParameter['nodeLevel'] - 1 ) );
		newParameter['RSA_Source'] |= ( newParameter['tempRSA_Source'] >> newParameter['nodeLevel'] );
	}
	else if ( mode ) {
		// destination
		if ( rule['cuttingCoordinate'][0] < newParameter['RSA_Destination'] )
			newParameter['RSA_Destination'] &= ~( newParameter['tempRSA_Destination'] >> ( newParameter['nodeLevel'] - 1 ) );
		newParameter['RSA_Destination'] |= ( newParameter['tempRSA_Destination'] >> newParameter['nodeLevel'] );
	}
	newParameter['nodeLevel']++;
	return newParameter;
};


function arar_create ( ruleList, parameter ) {
	let ARARTreeRoot = {};
	let srcRoot, destRoot;

	for (let i = 0; i < ruleList.length; i++){
		let tempRule, calRule;
		console.log(`\n\n[${i}th rule]\nthere are [${count}] ARARNodes.`);

		tempRule = segmentation( ruleList[i], parameter, false, true );
		calRule = deepcopy(tempRule);
		srcRoot = insert( srcRoot, calRule, ruleList[i], parameter, false );
		if ( tempRule['difference'] == true ) {
			calRule['value1'] = tempRule['value3'];
			calRule['value2'] = tempRule['value4'];
			srcRoot = insert( srcRoot, calRule, ruleList[i], parameter, false );
		}
		
		tempRule = segmentation( ruleList[i], parameter, true, true );
		calRule = deepcopy(tempRule);
		destRoot = insert( destRoot, calRule, ruleList[i], parameter, true );
		if ( tempRule['difference'] == true ) {
			calRule['value1'] = tempRule['value3'];
			calRule['value2'] = tempRule['value4'];
			destRoot = insert( destRoot, calRule, ruleList[i], parameter, true );
		}

		console.log(`\nARARTreeRoot:\n` + util.inspect( srcRoot, { showHidden: false, depth:null } ));
	}
	ARARTreeRoot['srcRoot'] = srcRoot;
	ARARTreeRoot['destRoot'] = destRoot;



	// console.log(`\nARARTreeRoot:\n` + util.inspect( ARARTreeRoot, { showHidden: false, depth:null } ));
	// console.log(`\nARARTreeRoot:\n` + util.inspect( ruleList, { showHidden: false, depth:null } ));
	return ARARTreeRoot;
};


function looking_for_region_segmentation_value ( ruleList ) {

	let maxSIP = ruleList[0]['source_ip']['__param__']['boardcastAddrValue'],
		maxDIP = ruleList[0]['destination_ip']['__param__']['boardcastAddrValue'];
	let parameter = new ARARParameter();
	
	for ( let i = 0; i < ruleList.length; i++) {
		if ( maxSIP < ruleList[i]['source_ip']['__param__']['boardcastAddrValue'] )
			maxSIP = ruleList[i]['source_ip']['__param__']['boardcastAddrValue'];
		if ( maxDIP < ruleList[i]['destination_ip']['__param__']['boardcastAddrValue'] )
			maxDIP = ruleList[i]['destination_ip']['__param__']['boardcastAddrValue'];
	};

	parameter['Max_Source'] = maxSIP;
	parameter['Max_Destination'] = maxDIP;
	parameter['RSA_Source'] = Math.pow(2, Math.floor(Math.log2( (maxSIP) >>> 0 )));
	parameter['tempRSA_Source'] = parameter['RSA_Source'];
	parameter['RSA_Destination'] = Math.pow(2, Math.floor(Math.log2( (maxDIP) >>> 0 )));
	parameter['tempRSA_Destination'] = parameter['RSA_Destination'];
	parameter['nodeLevel'] = 1;


	// console.log( myutils.ip_converter(parameter['Max_Source']) );

	return parameter;
};

function rule_list_convert ( ruleList ) {
	let newRuleList = [];
	for (let i=0; i<ruleList.length; i++){
		let rule = new ARARRule();
		rule['order'] = i;
		rule['max_sip'] = ruleList[i]['source_ip']['__param__']['boardcastAddrValue'];
		rule['min_sip'] = ruleList[i]['source_ip']['__param__']['networkAddrValue'];
		rule['max_dip'] = ruleList[i]['destination_ip']['__param__']['boardcastAddrValue'];
		rule['min_dip'] = ruleList[i]['destination_ip']['__param__']['networkAddrValue'];
		newRuleList.push(rule);
	}

	// console.log(`\nruleList:\n` + util.inspect( ruleList, { showHidden: false, depth:null } ));
	// console.log(`\nnewRuleList:\n` + util.inspect( newRuleList, { showHidden: false, depth:null } ));
	return newRuleList;
};


module.exports.start = start;