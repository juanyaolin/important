let Parameter = function ( level, rsv ) {
	return {
		'level': level,
		'rsv': rsv
	}
}

let Node = function( param ) {
	return {
		'param': param,
		'node0': undefined,
		'node1': undefined,
		'data': []
	};
};

let Data = function( order, data ) {
	return {
		'order': order,
		'data': data
	};
};

function data_difference ( node ) {
	for (let i=0; i<node['data'].length; i++)
		if ( node['data'][0]['data'] != node['data'][i]['data'] )
			return false;
	return true;
}

function update_parameter ( data, param ) {
	let newParam = deepcopy( param );
	if ( data < newParam['rsv'] )
		newParam['rsv'] &= ~( firstParam['rsv'] >> ( newParam['level'] - 1 ) );
	newParam['rsv'] |= ( firstParam['rsv'] >> newParam['level'] );
	newParam['level']++;

	// console.log(`\nnewParam of data[${data}]:\n` + util.inspect( newParam, { showHidden: false, depth:null } ) + `\n`);
	return newParam;
}

function segmentation ( node ) {
	

	if ( (node == null) || data_difference(node) )
		return node;

	for (let i=0; i<node['data'].length; i++){
		let block = Math.floor( node['data'][i]['data'] / node['param']['rsv'] );
		switch ( block ) {
			case 0:
				if ( node['node0'] == null ) {
					node['node0'] = new Node( update_parameter( node['data'][i]['data'], node['param'] ) );
				}
				node['node0']['data'].push( node['data'][i] );
				break;
			case 1:
				if ( node['node1'] == null ) {
					node['node1'] = new Node( update_parameter( node['data'][i]['data'], node['param'] ) );
				}
				node['node1']['data'].push( node['data'][i] );
				break;
			default:
				console.log( '[segmentation] block is [' + block + ']' );
				break;
		}
		// console.log( `data: ` + node['data'][i]['data'] + `      block: ` + block );
	}
	node['data'] = [];
	// console.log(`\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ) + `\n`);
	return node;	
}

function addToQueue ( node ) {
	queueIndex++;
	if ( queueProcess == queueIndex )
		console.log('queue full');
	queue[queueIndex] = node;
}

function deleteFromQueue () {
	queue[queueProcess] = null;
	if ( queueProcess == queueIndex )
		console.log('queue empty');
	queueProcess++;
	return queue[queueProcess];
}

let firstParam = new Parameter(1, 4);
let root = new Node( firstParam );
for (let i=0; i<10; i++) {
	let data = new Data(i, Math.floor( Math.random()*7) );
	root['data'].push(data);
}


// console.log(`\nroot:\n` + util.inspect( root, { showHidden: false, depth:null } ) + `\n`);

let queueIndex = 0,
	queueProcess = 0,
	node,
	queue = [];

addToQueue( root );
while (true) {
	node = deleteFromQueue();
	node = segmentation( node );
	if ( node != null ) {
		if ( node['node0'] != null )
			addToQueue( node['node0'] );
		if ( node['node1'] != null )
			addToQueue( node['node1'] );
		console.log( `[in if function]\nqueueIndex = ${queueIndex},  queueProcess = ${queueProcess}` );
	}
	else {
		console.log('infinite loop');
		break;
	}
}
// node['param']['level'] < 3


console.log(`\nroot:\n` + util.inspect( root, { showHidden: false, depth:null } ) + `\n`);
console.log(`\nqueue:\n` + util.inspect( queue, { showHidden: false, depth:null } ) + `\n`);




