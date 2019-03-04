# ResourceBundle Creator Script
Script to create a resource bundle for netwitness content

python resourcebundlecreator.py

Python script to create the initial folder structure of the resourceBundle
This creates a directory structure and also drops a readme.MD as well as another script that is run at the end to create the xml and zip file

creates structure like this:

>resourceBundleYYMMDD

>>APPRULE
  
>>>0.1
    
>FEED
  
>>0.1
    
>>>LOGCOLLECTOR
  
>0.1
  
>>LOGDEVICE
    
>>>0.1

>LUAPARSER
    
>>0.1
  
  MALWARERULE
    
    0.1
  
  REREPORT
    
    0.1
  
  RERULE
    
    0.1
  
  README.MD
  
  resourceBundleInfo.xml
  
  resourceBundleZipper.py
  
  Content is placed in the folder structures according to the readme file and the python script takes care of zipping the right content up and creating the xml file that links all the content together.
