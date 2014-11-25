jQuery(function($){
    var c = $('#console');
    var registerData;
    var authData;

    function log(prompt, message) {
        c.append("<dt>"+prompt+"</dt>");
        c.append("<dd>"+JSON.stringify(message)+"</dd>");
    };
    
    function register(d) {
        var clientData = JSON.parse(d.text());

        log("requested", clientData);

        u2f.register([clientData], [], function(data) {
            log("callback", data);
            if (data['errorCode']) return;
            var stringified = JSON.stringify(data);
            $('input#rr-body').val(stringified);
            $('form#registration-response').submit();
        });
    };

    function authenticate(d) {
        var clientData = JSON.parse(d.text());
        log("requested", clientData);

        u2f.sign([clientData], function(data) {
            log("callback", data);
            if (data['errorCode']) return;
            var stringified = JSON.stringify(data);
            $('textarea#sr-body').val(stringified);
            $('form#sign-response').submit();
        });
    };

    if ((registerData = $('#u2f-register-data')).length == 1) {
        $('#actually-register').click(function(){register(registerData);});
    }

    if ((authData = $('#u2f-sign-data')).length == 1) {
        $('#actually-sign').click(function(){authenticate(authData);});
    }
});
