import unittest

class TestSuisseIdAuthentication(unittest.TestCase):

    def createPlugin(self):
        from pas.plugins.suisseid.tests.utils import MockPAS
        from pas.plugins.suisseid.plugin import SuisseIDPlugin
        plugin = SuisseIDPlugin("suisseid")
        pas = MockPAS()
        return plugin.__of__(pas)
        
    def buildServerResponse(self):
        credentials={}
        credentials['suisseid.source'] = 'server'
        credentials['suisseid.attributes'] = {}
        credentials['login'] = '1234-1234-1234-1234'
        return credentials
        
    def testEmptyAuthentication(self):
        """ Test if we do not invent an identity out of thin air.
        """
        plugin = self.createPlugin()
        creds = plugin.authenticateCredentials({})
        self.assertEqual(creds, None)
        
    def testSuisseIDAuthentication(self):
        """ Test for empty suisseID number
        """
        credentials = self.buildServerResponse()
        plugin = self.createPlugin()
        creds = plugin.authenticateCredentials(credentials)
        self.assertEqual(creds, ('1234-1234-1234-1234', '1234-1234-1234-1234'))