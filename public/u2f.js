jQuery(function($){
    var c = $('#console');
    var d;

    function log(prompt, message) {
        c.append("<dt>"+prompt+"</dt>");
        c.append("<dd>"+JSON.stringify(message)+"</dd>");
    };
    
    function register(d) {
        var clientData = JSON.parse(d.text());

        var request = {
            challenge: clientData.challenge,
            version: "U2F_V2", 
            appId: clientData.origin
        };
  
        log("requested", request);

        u2f.register([request], [], function(data) {
            log("callback", data);
            if (data['errorCode']) return;
            var stringified = JSON.stringify(data);
            $('input#rr-body').val(stringified);
            $('input#rr-size').val(stringified.length);
            $('form#registration-response').submit();
        });
    };

    if ((d = $('#u2f-register-data')).length == 1) {
        $('#actually-register').click(function(){register(d);});
    }
});
