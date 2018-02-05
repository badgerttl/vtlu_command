import requests, json, os, ConfigParser, time
import splunk.Intersplunk

results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()

def vt_config():
	try:
		vt_conf_path = os.path.join(os.environ['SPLUNK_HOME'], 'etc/apps/vtlu/local/vtlu.conf')

		config = ConfigParser.ConfigParser()
		config.read(vt_conf_path)

		if config.has_section('settings'):
			if config.has_option('settings', 'api_key'):
						api_key = config.get('settings', 'api_key')
							
#					if config.has_option('settings', 'use_proxy'):
#						EnableProxy = config.getboolean('settings', 'use_proxy')

#					if config.has_option('settings', 'https_proxy'):
#						self.g_sHTTPS_Proxy = config.get('settings', 'https_proxy')

#					if HTTP_Proxy == None and HTTPS_Proxy == None:
#						EnableProxy = False
		return api_key
	except Exception, e:
			raise e

def vt_connect(api_key, type):
	params = {'apikey': api_key, 'resource': result[type]}
	headers = {
	"Accept-Encoding": "gzip, deflate",
	"User-Agent" : "gzip,  My Python requests library example client or username"
	}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
	params=params)
	return response
	
def vt_results(response):
	if "<Response [200]>" in str(response):
		report = response.json()
		if "Scan finished, information embedded" in report['verbose_msg']:
				result['vt_lookup'] = str(report['verbose_msg'])
				result['vt_detections'] = str(report['positives'])+'/'+str(report['total'])
				result['vt_link'] = str(report['permalink'])
				result['vt_scandate'] = str(report['scan_date'])
				result['md5'] = str(report['md5'])
				result['sha1'] = str(report['sha1'])
				result['sha256'] = str(report['sha256'])
		elif "The requested resource is not among the finished, queued or pending scans" in report['verbose_msg']:
				result['vt_lookup'] = str(report['verbose_msg'])
				result['vt_detections'] = "-"
				result['vt_link'] = "-"
				result['vt_scandate'] = "-"
	elif "<Response [200]>" not in str(response):
			result['vt_lookup'] = "Connection Error "+str(response)
			
try:
        for result in results:
                if "sha256" in result and len(result['sha256']) > 5:
                        type = 'sha256'
                elif "sha1" in result and len(result['sha1']) > 5:
                        type = 'sha1'
                elif "md5" in result and len(result['md5']) > 5:
                        type = 'md5'
                else:
                        result['vt_lookup'] = "Not a hash"
                        continue
		api_key = vt_config()
		response = vt_connect(api_key, type)
		result = vt_results(response)
		#time.sleep(15)
        splunk.Intersplunk.outputResults(results)
except:
    import traceback
    stack =  traceback.format_exc()
    results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))




