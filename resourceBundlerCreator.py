#!/usr/bin/env python

# build the folder structure for packaging

# version: 1.0
# date: 2019-02-01

import os
import uuid
import re
from datetime import datetime

# generate time for the resourceBundle name
now = datetime.now()
dir_name_date = now.strftime("%Y%m%d")

output_dir_master='resourceBundle'

#resourceBundle20190201
output_dir_name=output_dir_master+dir_name_date

output_dirs=['APPRULE','FEED','LOGDEVICE','LUAPARSER','MALWARERULE','REREPORT','RERULE','LOGCOLLECTOR']
output_dir_version = '0.1'
sep='/'

#-----------------------
readme_filename='README.md'
readme_contents="""
# How to use this resourceBundle creator script

Run the resourceBundleCreator.py file to generate the folder structure for the content to be uploaded to a RSA NetWitness System via RSA Live > Deploy

Each content piece requires a potentially different structure in the folder

Each content type folder needs a version folder inside it

Content is placed in the version folder
-------------------
##Currently working in this script:

APPLICATION RULES
LUAPARSERS
-------------------
Not working/Not implemented

All other folders

### APPLICATION RULES
--------------------
require clear text nwr files to be placed in the version folder
if there is more than 1 line per .nwr file then it will split the file into multiples (one line per file) and rename the original file to .multiline

### LUAPARSERS
--------------------
requires lua parser in the version folder
the script will zip the lua file up


To generate the bundle zip file execute the resourceBundleZipper.py which was added with the folders

THis will generate the resourceBundleInfo.xml file for the supported content and generate the resourceBundle<date>.zip file to be uploaded via RSA Live in NW head server.

"""
#------------------------
resourceZipperScript_name='resourceBundleZipper.py'
resourceZipperScript="""
#!/usr/bin/env python

# version: 1.0
# date: 2019-02-01

# written by eric partington , eric.partington@rsa.com
# can we upload .rules snort files?, index files?
 
# purpose:
#===========
# create the resource bundle for uploading to RSA NEtWitness via the RSA Live web page deploy bundle option

import os
import uuid
import re
from datetime import datetime
from zipfile import ZipFile

# generate time for the resourceBundle name
now = datetime.now()
dir_name_date = now.strftime("%Y%m%d")

output_dir_master='resourceBundle'

#-----------------------
resource_filename='resourceBundleInfo.xml'

# static
resource_header='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:resourceBundleInfo xmlns:ns2="com.rsa.smc.sa.live.bean.deployment">
    <resourceBundleDesc>Security Analytics Live Resource Bundle</resourceBundleDesc>
    <resourceInfoList>
'''

# this gets changed with each content piece of content
resource_info='''        <resourceInfo>
            <dependentNames></dependentNames>
            <displayName><dn></displayName>
            <fileName><fn></fileName>
            <filePath><fp></filePath>
            <productionVersion><v></productionVersion>
            <resourceType><rt></resourceType>
            <typeTitle><tt></typeTitle>
            <uuid><u></uuid>
        </resourceInfo>
'''

# static
resource_footer='''    </resourceInfoList>
    <buildVersion>11.2.0.1</buildVersion>
    <cmsServer>cms.netwitness.com</cmsServer>
</ns2:resourceBundleInfo>
'''

#-----------------------
#functions

# flip slashes from windows format to unix \ to / so that the resourcebundleinfo.xml works
def flip_slash(input):
    output=input.replace('\\\\','/')
    return output
    
# generate random UUID for the packager
def gen_uuid():
    return uuid.uuid1()
    
# given the path of a folder, get the last path as the version number for the resourcebundle.xml
def get_version(input):
    return os.path.basename(input)

#map the name to type title for xml output
def get_typeTitle(input):
    return {
        'LUAPARSER': 'Lua Parser',
        'APPRULE': 'Application Rule',
        'MALWARERULE': 'Malware Rules',
        'REREPORT': 'NetWitness Report',
        'LOGDEVICE': 'Log Device',
        'FEED': 'Feed',
        'RERULE': 'NetWitness Rule',
        'LOGCOLLECTOR': 'Log Collector',
    }.get(input, 'Unknown')  

# generate random UUID for the packager
def set_zip_extension(input):
    return input+'.zip'

#length of file (num lines)    
def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1
       
#-----------------------    
# this is the placeholder for the content info section
resource_info_all = ''

path = os.getcwd()  
print ("The current working directory is %s" % path)

resourceFolderName = os.path.basename(path)

file_paths = []

mylist = os.listdir(path)
# iterate over the folder structure and teh version inside it
for directory in mylist:
# LUAPARSER/0.1
    #read content, zip in place
    if directory == 'APPRULE':
        print ("Found %s" % directory)
        print ("** NOTE: This needs to be one rule per file, multiple rules per file breaks upload")
        
        res_path=''
        res_filename=''
        res_displayname=''
        res_version=''
        res_uuid=''
        
        for root, directories, files in os.walk(directory): 
            for filename in files: 
                # join the two strings in order to form the full filepath. 
                filepath = os.path.join(root, filename) 
                #file_paths.append(filepath)
                
                #if the file ends with apprule syntax
                if filepath.endswith('.nwr'):
                    
                    #read if the file has more than one line
                    if file_len(filepath) > 1 :
                        print ("multiline apprule found")
                        #split the file based on the lines
                        f = open(filepath, "r")
                        # use readlines to read all lines in the file
                        # The variable "lines" is a list containing all lines in the file
                        lines = f.readlines()
                        # close the file after reading the lines.
                        f.close()
                        #print(lines)
                        
                        #split on the extension
                        #tmp_name,file_ending = filename.split('.')
                        line_counter=1
                        
                        for nwr_line in lines:
                        #rename the original file to .multiline
                            #create a new file per line
                            #print ("		"+nwr_line)
                            
                            files.append(str(line_counter)+filename)
                            tmp_newfile=os.path.join(root,str(line_counter)+filename)
                            
                            with open(tmp_newfile, 'w') as file:
                                print(tmp_newfile)
                                # Use file to refer to the file object
                                file.write(nwr_line)
                            #increment the counter for lines in file
                            line_counter += 1
                            #add the new filenaem to the list of files in the directory
                         
                            
                        #rename the file to .multiline
                        #filename = filename+".multiline"    
                        os.rename(os.path.join(root,filename), os.path.join(root,filename+".multiline"))
                    
                    else:
                        #res_version=os.path.basename(root)
                        res_version = get_version(root)
                        
                        #this is teh resourcetype (LUAPARSER)
                        res_resourcetype = directory
                        
                        #split on the extension
                        #res_displayname,file_ending = filename.split('.')
                        filename_parts = filename.split('.')
                        
                        # If this is the renamed file there will be 2 periods and length of 3 so we should skip adding that one
                        if len(filename_parts) == 2:
                            res_displayname = filename_parts[0]
                            #append the zip extension to the filename
                            #res_filename = res_displayname+'.zip'
                            res_filename = filename
                            
                            res_filepath = os.path.join(root,res_filename)
                            
                            # flip the slashes from windows to linux style
                            #res_filepath_switched=res_filepath.replace('','/')
                            res_filepath_switched = flip_slash(res_filepath)
                            
                            #res_typetitle = 'Lua Parser'
                            #get the typeTitle equivalent (Lua Parser) of the resource type (LUAPARSER)
                            res_typetitle = get_typeTitle(res_resourcetype)
                            
                            #generate UUID for the resource - random
                            #res_uuid=uuid.uuid1()
                            res_uuid = gen_uuid()
                            
                            #print(root)
                            #print(res_version)
                            #print(res_resourcetype)
                            #print(res_displayname)
                            print("	"+res_filename)
                                
                            #update the resourc bundle strings
                            resource_info_tmp = resource_info.replace('<fn>',res_filename)
                            resource_info_tmp = resource_info_tmp.replace('<v>',res_version)
                            resource_info_tmp = resource_info_tmp.replace('<rt>',res_resourcetype)
                            resource_info_tmp = resource_info_tmp.replace('<fp>',res_filepath_switched)
                            resource_info_tmp = resource_info_tmp.replace('<dn>',res_displayname)
                            resource_info_tmp = resource_info_tmp.replace('<tt>',res_typetitle)
                            resource_info_tmp = resource_info_tmp.replace('<u>',str(res_uuid))
                            
                            resource_info_all += resource_info_tmp
                            
                            #print(resource_info_tmp)
                            file_paths.append(filepath)
                    
    elif directory == 'FEED':
        print ("Found %s" % directory)
        print ("  Not supported yet")
        # Do the other thing
        # zip
    elif directory == 'LOGDEVICE':
        print ("Found %s" % directory)
        print ("  Not supported yet")
        # Do the other thing
        # zip as envision
    elif directory == 'LUAPARSER':
        print ("Found %s" % directory)
        # open the directory, capture the name, open that, capture the filename.lua, zip it
        res_path=''
        res_filename=''
        res_displayname=''
        #res_type=directory
        res_version=''
        res_uuid=''
        
        for root, directories, files in os.walk(directory): 
            for filename in files: 
                # join the two strings in order to form the full filepath. 
                filepath = os.path.join(root, filename) 
                #file_paths.append(filepath)
                
                if filepath.endswith('.lua'):
                    #we are in the right place to find lua files
                    #print(filepath)
                    #print(root)
                    #print(directory)
                    
                    #res_version=os.path.basename(root)
                    res_version = get_version(root)
                    
                    #this is teh resourcetype (LUAPARSER)
                    res_resourcetype = directory
                    
                    #split on the extension
                    res_displayname,file_ending = filename.split('.')
                    
                    #append the zip extension to the filename
                    #res_filename = res_displayname+'.zip'
                    res_filename = set_zip_extension(res_displayname)
                    
                    res_filepath = os.path.join(root,res_filename)
                    
                    # flip the slashes from windows to linux style
                    #res_filepath_switched=res_filepath.replace('','/')
                    res_filepath_switched = flip_slash(res_filepath)
                    
                    #res_typetitle = 'Lua Parser'
                    #get the typeTitle equivalent (Lua Parser) of the resource type (LUAPARSER)
                    res_typetitle = get_typeTitle(res_resourcetype)
                    
                    #generate UUID for the resource - random
                    #res_uuid=uuid.uuid1()
                    res_uuid = gen_uuid()
                    
                    #print(root)
                    #print(res_version)
                    #print(res_resourcetype)
                    #print(res_displayname)
                    print("	"+res_filename)
                        
                    # writing files to a zipfile 
                    with ZipFile(res_filepath,'w') as zip:
                        zip.write(filepath, filename)
                    
                    #add the zip to the list of files to add
                    file_paths.append(res_filepath)
                    
                    #update the resourc bundle strings
                    resource_info_tmp = resource_info.replace('<fn>',res_filename)
                    resource_info_tmp = resource_info_tmp.replace('<v>',res_version)
                    resource_info_tmp = resource_info_tmp.replace('<rt>',res_resourcetype)
                    resource_info_tmp = resource_info_tmp.replace('<fp>',res_filepath_switched)
                    resource_info_tmp = resource_info_tmp.replace('<dn>',res_displayname)
                    resource_info_tmp = resource_info_tmp.replace('<tt>',res_typetitle)
                    resource_info_tmp = resource_info_tmp.replace('<u>',str(res_uuid))
                    
                    resource_info_all += resource_info_tmp
                    
                    #print(resource_info_tmp)
                else:
                    if filepath.endswith('.zip'):
                        #only add teh zipped entries to the list to be zipped in total later
                        file_paths.append(filepath)
            
    elif directory == 'MALWARERULE':
        print ("Found %s" % directory)
        print ("  Not supported yet")
        # Do the other thing
        # no zip
    elif directory == 'REREPORT':
        print ("Found %s" % directory)
        print ("  Not supported yet")
        # Do the other thing
        # no zip, url encode
    elif directory == 'RERULE':
        print ("Found %s" % directory)
        print ("  Not supported yet")
        # Do the other thing
        # no zip, url encode
    elif directory == 'LOGCOLLECTOR':
        print ("Found %s" % directory)
        print ("  Not supported yet")
        # Do the other thing
        # zip, rename to .logcollection
    elif directory == 'resourceBundleInfo.xml':
        print ("Found %s" % directory)
        # 
        # join the two strings in order to form the full filepath. 
        #filepath = os.path.join(root, directory) 
        file_paths.append(directory)
    else:
        print ("** Probably the script and readme.md will be here")
        print ("** Found %s" % directory)
        # Do the default
        # spit error out
 
# now that we have all the files zipped we need, create the xml to link them all 
# concat all the values together for the resource bundle writing
bundle_filename_contents=resource_header+resource_info_all+resource_footer
            
#write out resourceBundleInfo.xml
with open(resource_filename, 'w') as f:
    f.write(bundle_filename_contents)
    print ("Successfully created the resourceBundle file %s " % resource_filename)
    file_paths.append(resource_filename)
    
# completed the resource bundle xml file writing to root of directory

# write out the zip package for the whole thing in the same root directory
print("Following files will be zipped:") 
for file_name in file_paths: 
    print(file_name) 
    
# writing files to a zipfile 
with ZipFile(set_zip_extension(resourceFolderName),'w') as zip: 
    # writing each file one by one 
    for file in file_paths: 
        zip.write(file) 

print("Wrote output zip for %s" % set_zip_extension(resourceFolderName))
"""

#------------------------
path = os.getcwd()  
print ("The current working directory is %s" % path)

working_dir = os.path.join(path, output_dir_name)

#create high level bundle folder (all others are inside it)
try:  
    #os.mkdir(path+sep+output_dir_name)
    os.mkdir(working_dir)
except OSError:
    print ("Creation of the directory %s failed" % output_dir_name)
else:  
    print ("Successfully created the directory %s " % output_dir_name)
    #we have top level started now go in a level
    
    #if dir creation was success create the rest of the files
    
    #write out readme.md
    with open(os.path.join(working_dir, readme_filename), 'w') as f:
            f.write(readme_contents)
            print ("Successfully created the file %s " % readme_filename)
    
    #write out resourceBundleZipper.py
    with open(os.path.join(working_dir , resourceZipperScript_name), 'w') as f:
            f.write(resourceZipperScript)
            print ("Successfully created the file %s " % resourceZipperScript_name)
    
    #iterate over list of folders to create for content
    for i in output_dirs:
        try:  
            os.makedirs(working_dir+sep+i+sep+output_dir_version)
        except OSError:
            print ("Creation of the directory %s failed" % i)
        else:  
            print ("Successfully created the directory %s " % i)
