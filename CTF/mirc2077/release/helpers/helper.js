/* Credits: https://github.com/saelo/jscpwn */
/* UTILITIES */

/* fix-up for duktape */
function ArrayFrom(val) {
	r = Array();
	for(i = 0; i < val.length; i++) {
		r.push(val[i]);
	}
}
function ArrayFromRev(val) {
	r = Array();
	for(i = 0; i < val.length; i++) {
		r.push(val[i]);
	}
	return r.reverse();
}

function hexu(val) {
	return "0x" + val.toString(16);
}

function print_val(ptr, i) {
	console.log("val 0x" + ptr[i].toString(16));
}

function log(data) {
	console.log(data);
}

// Return the hexadecimal representation of the given byte.
function hex(b) {
	return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
	var res = [];
	for (var i = 0; i < bytes.length; i++)
			res.push(hex(bytes[i]));

	return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
	if (hexstr.length % 2 == 1)
			throw new TypeError("Invalid hex string");

	var bytes = new Uint8Array(hexstr.length / 2);
	for (var i = 0; i < hexstr.length; i += 2)
			bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);
	return bytes;
}

var Struct = (function() {
	// Allocate these once to avoid unecessary heap allocations during pack/unpack operations.
	var buffer      = new ArrayBuffer(8);
	var byteView    = new Uint8Array(buffer);
	var uint32View  = new Uint32Array(buffer);
	var float64View = new Float64Array(buffer);

	return {
			pack: function(type, value) {
					var view = type;        // See below
					view[0] = value;
					return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
			},

			unpack: function(type, bytes) {
					if (bytes.length !== type.BYTES_PER_ELEMENT)
							throw Error("Invalid bytearray");

					var view = type;        // See below
					byteView.set(bytes);
					return view[0];
			},

			// Available types.
			int8:    byteView,
			int32:   uint32View,
			float64: float64View
	};
})();

function Int64(v) {
	// The underlying byte array.
	var bytes = new Uint8Array(8);

	switch (typeof v) {
			case 'number':
					v = '0x' + Math.floor(v).toString(16);
			case 'string':
					if (v.startsWith('0x'))
							v = v.substr(2);
					if (v.length % 2 == 1)
							v = '0' + v;

					var bigEndian = unhexlify(v, 8);
					bytes.set(ArrayFromRev(bigEndian));
					break;
			case 'object':
					if (v instanceof Int64) {
							bytes.set(v.bytes());
					} else {
							if (v.length != 8)
									throw TypeError("Array must have excactly 8 elements.");
							bytes.set(v);
					}
					break;
			case 'undefined':
					break;
			default:
					throw TypeError("Int64 constructor requires an argument.");
	}

	// Return a double whith the same underlying bit representation.
	this.asDouble = function() {
			// Check for NaN
			if (bytes[7] == 0xff && (bytes[6] == 0xff || bytes[6] == 0xfe))
					throw new RangeError("Integer can not be represented by a double");

			return Struct.unpack(Struct.float64, bytes);
	};

	// Return a javascript value with the same underlying bit representation.
	// This is only possible for integers in the range [0x0001000000000000, 0xffff000000000000)
	// due to double conversion constraints.
	this.asJSValue = function() {
			if ((bytes[7] == 0 && bytes[6] == 0) || (bytes[7] == 0xff && bytes[6] == 0xff))
					throw new RangeError("Integer can not be represented by a JSValue");

			// For NaN-boxing, JSC adds 2^48 to a double value's bit pattern.
			this.assignSub(this, 0x1000000000000);
			var res = Struct.unpack(Struct.float64, bytes);
			this.assignAdd(this, 0x1000000000000);

			return res;
	};

	// Return the underlying bytes of this number as array.
	this.bytes = function() {
			return ArrayFrom(bytes);
	};

	// Return the byte at the given index.
	this.byteAt = function(i) {
			return bytes[i];
	};

	// Return the value of this number as unsigned hex string.
	this.toString = function() {
			return '0x' + hexlify(ArrayFromRev(bytes));
	};

	// Basic arithmetic.
	// These functions assign the result of the computation to their 'this' object.

	// Decorator for Int64 instance operations. Takes care
	// of converting arguments to Int64 instances if required.
	function operation(f, nargs) {
			return function() {
					if (arguments.length != nargs)
							throw Error("Not enough arguments for function " + f.name);
					for (var i = 0; i < arguments.length; i++)
							if (!(arguments[i] instanceof Int64))
									arguments[i] = new Int64(arguments[i]);
					return f.apply(this, arguments);
			};
	}

	// this = -n (two's complement)
	this.assignNeg = operation(function neg(n) {
			for (var i = 0; i < 8; i++)
					bytes[i] = ~n.byteAt(i);

			return this.assignAdd(this, Int64.One);
	}, 1);

	// this = a + b
	this.assignAdd = operation(function add(a, b) {
			var carry = 0;
			for (var i = 0; i < 8; i++) {
					var cur = a.byteAt(i) + b.byteAt(i) + carry;
					carry = cur > 0xff | 0;
					bytes[i] = cur;
			}
			return this;
	}, 2);

	// this = a - b
	this.assignSub = operation(function sub(a, b) {
			var carry = 0;
			for (var i = 0; i < 8; i++) {
					var cur = a.byteAt(i) - b.byteAt(i) - carry;
					carry = cur < 0 | 0;
					bytes[i] = cur;
			}
			return this;
	}, 2);
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromDouble = function(d) {
	var bytes = Struct.pack(Struct.float64, d);
	return new Int64(bytes);
};

// Convenience functions. These allocate a new Int64 to hold the result.
// Return -n (two's complement)
function Neg(n) {
	return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
	return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
	return (new Int64()).assignSub(a, b);
}

function d2i(val) {
	return new Int64.fromDouble(val);
}

function h2i(val) {
	return new Int64(val);
}

function h2d(val) {
  return h2i(val).asDouble();
}

function i2d(val) {
	return new Int64(val).asDouble();
}