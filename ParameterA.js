// console.log("Hello, World.This sentence is written using JavaScript.");



// var fs = require('fs');

// fs.readFile('./test.txt', 'utf8', function(err, contents){
// 	console.log(contents);
// });
// console.log('after calling readFile');


var max_S = 0b11000000101010000000000011011111;
var min_S = 0b11000000101010000000000000000000;
var max_D = 0b11000000101010000000000111010010;
var min_D = 0b11000000101010000000000100010110;


function InitialParameterA(max_S, min_S, max_D, min_D)
{
	
	var mask = Math.pow(2, 32) - 1;
	//  mask = 0b11111111111111111111111111111111
	//       = 255.255.255.255
	var base_S, base_D, init_A;
	
	var tempA_S = Math.pow(2, Math.floor(Math.log2(max_S^min_S)));
	var tempA_D = Math.pow(2, Math.floor(Math.log2(max_D^min_D)));

	init_A = tempA_S > tempA_D ? tempA_S : tempA_D;
	mask = ( mask << (Math.log2(init_A)+1) ) >>> 0;
	
	base_S = (min_S & mask) >>> 0;
	base_D = (min_D & mask) >>> 0;

	return {init_A, base_S, base_D};
}

console.log((InitialParameterA(max_S, min_S, max_D, min_D)).base_S.toString(2));
console.log((InitialParameterA(max_S, min_S, max_D, min_D)).base_D.toString(2));
console.log((InitialParameterA(max_S, min_S, max_D, min_D)).init_A.toString(2));
// console.log('max_S =\n'+ max_S.toString(2));
// console.log('min_S =\n'+ min_S.toString(2));
// console.log('max_D =\n'+ max_D.toString(2));
// console.log('min_D =\n'+ min_D.toString(2));

var max = 0b01101100;
var min = 0b01000001;

function inita(max, min){
	var init_A = max ^ min;
	while( (init_A & (init_A-1)) )
		init_A = init_A & (init_A-1);
	return init_A;
};

console.log(inita(max, min).toString(2));