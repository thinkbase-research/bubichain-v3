var http = require('http');
var querystring = require('querystring');

var nonce = 0;
var host='127.0.0.1';
var port = 39333;

 setInterval(function(){
	 f1();
 }, 100);
 
function f1(){
  var http = require('http');
  var querystring = require('querystring');
  var options = {
    host : host,
    port : port,
    path : '/createAccount',
    method : 'GET',
    headers : {
      'Content-Type' : 'application/json'
    }
  };
  http.get(options, function (res) {
    var resData = "";
    res.on("data", function (data) {
      resData += data;
    });
    res.on("end", function () {
      var address = JSON.parse(resData).result.address;
	  createAccount(address);
    });
  })
}

function createAccount(address) {
	console.log(address);
	//return;
  nonce++;
  var txItems = {
    "items" : [{
        "transaction_json" : {
          "source_address" : "a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18",
          "nonce" : nonce,
          "operations" : [{
              "type" : "CREATE_ACCOUNT",
              "create_account" : {
                "dest_address" : address,
				"priv":{
					"thresholds":{
						"tx_threshold":0
					}
				}
              }
            }
          ]
        },
        "private_keys" : [
          "c00205ce8de2892b26c3b95caf3404831d6e913c655d85b517f076380ebfcbef47ff8f"
        ]
      }
    ]
  };

  var content = JSON.stringify(txItems);

  var options = {
    host : host,
    port : port,
    path : '/submitTransaction',
    method : 'POST',
    headers : {
      'Content-Type' : 'application/x-www-form-urlencoded',
      'Content-Length' : content.length
    }
  };

  var req = http.request(options, function (res) {
      res.on('data', function (data) {
        //console.log(data);
      });
      res.on('error', function (err) {
        console.log(err);
      });
    });

  req.write(content);
  req.end();
  console.log(content);
}
