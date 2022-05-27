# -*- coding: utf-8 -*-
  
from virustotal_python import Virustotal
import os.path
 
from base64 import urlsafe_b64encode
import pandas as pd
 
API_KEY =  
#URLS = ["google.com", "wikipedia.com", "github.com", "ihaveaproblem.info"]
u=pd.read_csv('test.csv')

URLS=[]
URLS=u['URL'] 
 
 



 
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

for url in URLS:
    # Send the URL to VirusTotal for analysis
    resp = vtotal.request("urls", data={"url": url}, method="POST")
 
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    print(f"URL: {url} ID: {url_id}")
    # Obtain the analysis results for the URL using the url_id
    analysis_resp = vtotal.request(f"urls/{url_id}")
    print(analysis_resp.object_type)

    #pprint(analysis_resp.data)
    df=analysis_resp.data
    a=df['attributes']['last_analysis_stats']['harmless']
    b=df['attributes']['last_analysis_stats']['malicious']
    print('Stats for this website are: ',df['attributes']['last_analysis_stats'] )  
    if b>1:
      print('This is a Malacious link')
    else:
      print('This is a safe link')