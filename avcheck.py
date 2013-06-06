import simplejson
import urllib
import urllib2
def check(rsc,file):
    url= "https://www.virustotal.com/vtapi/v2/file/report"
    parameters= {"resource":rsc,"apikey":"56d682dc798fdb96f8a570b3e99f8472a7d132f76da84f1fab2ea0b02812f68a"}  
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url,data)
    response = urllib2.urlopen(req)
    try:
     dt=simplejson.load(response)
    except:
     return file+": Server Error"
    if dt and dt.get('positives'):
     return "%s INFECTED Detections:%d AV "%(file,dt.get('positives'))
    else:
     return "%s CLEAN"%(file)
