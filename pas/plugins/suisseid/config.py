import os
path = os.path.dirname(__file__)

sp_config = {
    
    "entityid" : "",
    "service": {
        "sp":{
            "name" : "",
            "url" : "",
            "required_attributes": [],
            "optional_attributes": [],
            "privacy_notice": "",
            "idp": { },
        }
    },
    "metadata" : {
        "local" : [],
    },
    "debug" : 0,
    "key_file" : "",
    "cert_file" : "",
    "xmlsec_binary" : "/usr/bin/xmlsec1",
    "organization": {
        "name": "",
        "display_name": "",
        "url":"",
    },
    "contact": [{
        "given_name":"",
        "sur_name": "",
        "email_address": "",
        "contact_type": "",
    }]
    
}
