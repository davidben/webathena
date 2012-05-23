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
        if(fail)
            return false;
        
        var text = $('#submit').text();
        $('#submit').attr('disabled', 'disabled').text('.');
        var interval = setInterval(function() {
          $('#submit').text(($('#submit').text() + '.').replace('.....', '.'));
        }, 500);
        var reset = function() {
            clearInterval(interval);
            $('#submit').attr('disabled', null).text(text);
        };
        KDC.asReq(username, function(reply) {
            console.log(username);
            console.log(reply);
            reset();
        }, function(error) {
            console.log("Error in AS_REQ: " + error); // TODO actual error reporting
            reset();
        });
        return false;
    });
});
