$.ajaxSetup({
    cache: false,
    contentType: 'text/plain',
    dataType: 'json',
    headers: { 'X-WebKDC-Request' : 'OK' },
    type: 'POST',
});

KDC = {
    URL_BASE: '/kdc/v1/',
    asReq: function(success, error) {
        $.ajax(this.URL_BASE + 'AS_REQ', {
            data: CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(':-Þ')),
            error: function(xhr, status, error) {
                var msg = status || 'unknown error';
                if(error)
                    msg += ': ' + error;
                error(msg);
            },
            success: function(data, status, xhr) {
                switch(data.status) {
                    case 'ERROR':
                        error(data.msg);
                        break;
                    case 'TIMEOUT':
                        error('KDC connection timed out');
                        break;
                    case 'OK':
                        success(data.reply);
                        break;
                }
            },
        });
    },
};

KDC.asReq(function(reply) {
    console.log(reply);
}, function(error) {
    alert(error);
});
