"use strict";

var HEX_DIGITS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                  "A", "B", "C", "D", "E", "F"];

function arrayToHex(array) {
    return escape(String.fromCharCode.apply(String, array));
}

function arraysEqual(value, expected, msg) {
    equal(arrayToHex(value), arrayToHex(expected), msg);
}
