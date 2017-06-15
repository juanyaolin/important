module.exports.ip_converter = function ip_converter ( ipData ) {
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
