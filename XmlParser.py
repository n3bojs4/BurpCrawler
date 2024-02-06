from contextlib import nullcontext
import xml.etree.ElementTree as ET
import base64
import os
import uuid


# Config
XMLFILE='YOURFILE.xml'


# Create a class for parsing burp requests file
class BurpReq:
    def __init__(self, url, method, status, cookie, path):
        self.url = url
        self.method = method
        self.status = status
        self.cookie = cookie
        self.path = path


# Creating subfolder

current_dir=os.path.abspath('.')+'/'

DirID = str(uuid.uuid1())

DirPath = current_dir+DirID

try:
    os.mkdir(DirPath)
except:
    print("Cannot create dir",DirPath)
    exit(1)

print(DirPath,"directory has been created for saving files !")




# Parsing burp xml file
tree = ET.parse(XMLFILE)


root = tree.getroot()

requests=[]

# Clear the cookie file
open(DirPath+"/cookies.txt", 'w').close()


# Reading data from burp file and storing object instances into requests dict
for i in range(0,len(root)):
    url=root[i][1].text
    method=root[i][5].text
    path=root[i][6].text
    base64req=root[i][8].text
    respStatus=root[i][9].text
    cookie=None


    req=base64.b64decode(base64req).decode("utf-8").split('\n')

    for line in req:
        if "Cookie: " in line:
            cookie=line.replace('Cookie: ', '')

    
    request = BurpReq(url,method,respStatus,cookie,path)
    requests.append(request)



# Generating cookies file
print('Generating '+DirID+'/cookies.txt file')

for record in requests:

    domain=str(record.url).split("/")[2]
    flag="TRUE"
    path=record.path
    secure="FALSE"
    expiration="2996684799"
    name=record.cookie
    value="FAKE"

    if record.cookie:

        for x in record.cookie.split(';'):
            f = open(DirPath+"/cookies.txt", "a")
            domain=str(record.url).split("/")[2]
            flag="TRUE"
            path=record.path
            secure="FALSE"
            expiration="2996684799"

            name=x.split("=")[0]
            value=x.split("=")[1]
            MyCookie=domain+"\t"+flag+"\t"+path+"\t"+secure+"\t"+expiration+"\t"+name+"\t"+value+"\n"
            f.write(MyCookie)
            f.close()


        

        
# Generating wget bash script for scraping
for record in requests:
    f = open(DirPath+"/wget.sh", "a")
    command="wget -x"+" --no-check-certificate"+" --load-cookies=cookies.txt "+record.url+"\n"
    f.write(command)
    f.close()


# Changing rights on wget.sh and execute it !
try:
    os.chmod(DirPath+"/wget.sh", 0o755)
    os.chdir(DirPath)
    os.system('./wget.sh')
except:
    print('wget script failed to execute !')




    



