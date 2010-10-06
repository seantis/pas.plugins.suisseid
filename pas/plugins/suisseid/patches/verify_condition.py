import time
import dateutil.parser

from saml2.client import for_me

def _use_on_or_after(condition, slack):
    now = time.mktime(time.gmtime())
    not_on_or_after = dateutil.parser.parse(condition.not_on_or_after)
    not_on_or_after = time.mktime(not_on_or_after.utctimetuple())
    if not_on_or_after < now + slack:
        # To old ignore
        raise Exception("To old can't use it (%s < %s)" % ( not_on_or_after,
                        (now + slack)))
    return not_on_or_after
    
def _use_before(condition, slack):
    not_before = dateutil.parser.parse(condition.not_before)
    not_before = time.mktime(not_before.utctimetuple())
    now = time.mktime(time.gmtime())
        
    if not_before > now + slack:
        # Can't use it yet
        raise Exception("Can't use it yet %s > %s" % (not_before, now))

def _verify_condition(self, assertion, requestor, log, lax=False, 
                        slack=0):
    # The Identity Provider MUST include a <saml:Conditions> element
    #print "Conditions",assertion.conditions
    assert assertion.conditions
    condition = assertion.conditions
    log and log.info("condition: %s" % condition)

    try:
        slack = self.config["accept_time_diff"]
    except KeyError:
        slack = 0

    try:
        not_on_or_after = _use_on_or_after(condition, slack)
        _use_before(condition, slack)
    except Exception:
        if not lax:
            raise
        else:
            not_on_or_after = 0
            
    if not for_me(condition, requestor):
        raise Exception("Not for me!!!")
    
    return not_on_or_after