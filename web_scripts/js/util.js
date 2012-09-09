sjcl.random.startCollectors();
window.getRandomBytes = function(nBytes) {
    return sjcl.random.randomWords(Math.ceil(nBytes / 4));
};

function log() {
    if (console && console.log)
        console.log(arguments);
}
