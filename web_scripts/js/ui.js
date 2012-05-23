$(function() {
    $('#whatis').click(function() {
        $('#info').slideToggle();
        return false;
    });
    
    $('form').submit(function() {
        var username = this.username.value,
            password = this.password.value,
            fail = false;
        if(!username) {
            $('#username + .error').fadeIn();
            fail = true;
        } else {
            $('#username + .error').fadeOut();
        }
        if(!password) {
            $('#password + .error').fadeIn();
            fail = true;
        } else {
            $('#password + .error').fadeOut();
        }
        if(!fail) {
            console.log(username, password);
            $(this.submit).attr('disabled', 'true').text('.');
            setInterval(function() {
              $('#submit').text(($('#submit').text() + '.').replace('.....', '.'));
            }, 500);
            KDC.asReq(function(reply) {
                console.log(reply);
            }, function(error) {
                console.log("Error in AS_REQ: " + error);
            });
        }
        return false;
    });
});
