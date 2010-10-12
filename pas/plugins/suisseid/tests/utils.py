import sgmllib
import Acquisition

class MockResponse(object):
    
    def __init__(self):
        self.status = None
        self.headers = {}
        self.body = ''
        
    def setStatus(self, status, lock=False):
        self.status = status
        
    def setHeader(self, key, value):
        self.headers[key] = value
        
    def setBody(self, body, lock=False):
        self.body = body
        

class MockRequest(object):
    
    ACTUAL_URL = "http://nohost/"
    
    def __init__(self):
        self.RESPONSE = self.response = MockResponse()
        self.SESSION = {}
        self.environ = {}
        self.form = dict(SESSION=dict())

    def __getitem__(self, key):
        return self.form.get(key)


class MockPAS(Acquisition.Implicit):
    
    def __init__(self):
        self.REQUEST = MockRequest()
        
    def updateCredentials(self, request, response, login, new_password):
        pass
        
class FormParser(sgmllib.SGMLParser):
    
    def __init__(self, verbose=0):
        sgmllib.SGMLParser.__init__(self, verbose)
        self.inputs = {}
    
    def parse(self, s):
        self.feed(s)
        self.close()
        
    def start_input(self, attributes):
        name = value = None
        for attr_key, attr_value in attributes:
            if attr_key == 'name':
                name = attr_value
            if attr_key == 'value':
                value = attr_value
        if name is not None and value is not None:
            self.inputs[name] = value