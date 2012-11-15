sjcl.random.startCollectors();
window.getRandomBytes = function(nBytes) {
    return sjcl.random.randomWords(Math.ceil(nBytes / 4));
};

function log(arg) {
    if (typeof console != "undefined" && console.log)
        console.log(arg);
}
