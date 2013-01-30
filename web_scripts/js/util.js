function log(arg) {
    if (typeof console != "undefined" && console.log)
        console.log(arg);
}

if (!Object.create) {
    Object.create = function (o) {
        if (arguments.length > 1) {
            throw new Error('Object.create implementation only accepts the first parameter.');
        }
        function F() {}
        F.prototype = o;
        return new F();
    };
}

if (!window.atob) {
    window.atob = function(a) {
        return sjcl.codec.byteString.fromBits(sjcl.codec.base64.toBits(a));
    };
}
if (!window.btoa) {
    window.btoa = function(b) {
        return sjcl.codec.base64.fromBits(sjcl.codec.byteString.toBits(b));
    };
}

// This is too useful to not polyfill.
if (!Function.prototype.bind) {
    Function.prototype.bind = function (oThis) {
        if (typeof this !== "function") {
            // closest thing possible to the ECMAScript 5 internal
            // IsCallable function
            throw new TypeError("Not callable");
        }

        var aArgs = Array.prototype.slice.call(arguments, 1),
            fToBind = this,
            fNOP = function () {},
            fBound = function () {
                return fToBind.apply(this instanceof fNOP && oThis
                                     ? this
                                     : oThis,
                                     aArgs.concat(Array.prototype.slice.call(arguments)));
            };

        fNOP.prototype = this.prototype;
        fBound.prototype = new fNOP();

        return fBound;
    };
}
