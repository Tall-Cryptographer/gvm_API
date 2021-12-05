from os import truncate
import sys
from colorama.ansi import Fore
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv208.entities.credentials import CredentialType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm
from gvm.transforms import EtreeCheckCommandTransform
from gvm.protocols.gmpv214 import FilterType
from gvm.xml import pretty_print
import gvm
from gvm.protocols.gmpv214 import CredentialType
from colorama import init
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from lxml import etree

# connect to the GVM

path = '/var/run/gvm/gvmd.sock'
connection = UnixSocketConnection(path=path)
transform = EtreeCheckCommandTransform()

username = 'danial'
password = '@npSec2016'

try:
    tasks = []

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(username, password)

        tasks = gmp.get_tasks(filter_string='name~weekly')

        for task in tasks.xpath('task'):
            print(task.find('name').text)

except GvmError as e:
    print('An error occurred', e, file=sys.stderr)

#---------------------------------------------------------------------
# create credential

print(Fore.CYAN+'create credential')
name_cred = input(Fore.WHITE+'Enter name of credential: ')
commentt = input(Fore.WHITE+'Enter comment for credential : ')
type_cred = int(input('which type do you want? \n 1-Username and Password \n 2-SNMP \n 3-Password only \n PLEASE ENTER THE NUMBER : '))
if type_cred == 1:
    gmp.create_credential(
        name= name_cred,
        comment=commentt,
        credential_type=CredentialType.USERNAME_PASSWORD,
        login= input('Enter username : '),
        password= input('Enter password : ')
    )
elif type_cred == 2:
        gmp.create_credential(
        name= name_cred,
        comment=commentt,
        credential_type=CredentialType.SNMP,
        login= input('Enter username : '),
        password= input('Enter password : '),
        privacy_password= input('Enter privacy password : '),
        auth_algorithm= SnmpAuthAlgorithm(input('auth : MD5 or SHA1 ')),
        privacy_algorithm= SnmpPrivacyAlgorithm(input('algorithm : AES , DES or None '))
    )
elif type_cred == 3:
        gmp.create_credential(
        name= name_cred,
        comment=commentt,
        credential_type=CredentialType.PASSWORD_ONLY,
        password = input('Enter password :'),
    )
all_cred = gmp.get_credentials()
for i in all_cred.findall('credential'):
    if i[1].text==name_cred:
        cred_id = i.get('id')
print('--------------------------------------------------------------')
#---------------------------------------------------------------------
# create port list

# print(Fore.CYAN+'create port list')
# gmp.create_port_list(
#     name= input(Fore.white+'Enter name of port list :'),
#     port_range= input('port range :')
# )
# print('--------------------------------------------------------------')
#----------------------------------------------------------------------
#creat target

if type_cred == 2:
    print(Fore.CYAN+'create target')
    t=gmp.create_target(
        name= input(Fore.WHITE+'Enter name of target : '),
        comment= input('Enter comment : '),
        hosts= [input('Enter hosts : ')],
        snmp_credential_id=cred_id,
        port_range= input('Enter port range : ')
    )
    danial_target_id = t.xpath('@id')[0]
else:
    print(Fore.CYAN+'create target')
    t=gmp.create_target(
        name= input(Fore.WHITE+'Enter name of target : '),
        comment= input('Enter comment : '),
        hosts= [input('Enter hosts : ')],
        port_range= input('Enter port range : ')
    )
    danial_target_id = t.xpath('@id')[0]
print('--------------------------------------------------------------')
#-----------------------------------------------------------------------
# create task

print(Fore.CYAN+'create task')
##openvas_default
type_scanner = int(input(Fore.WHITE+'which scanner do yo want? \n 1-openvas-default \n 2-CVE \n PLEASE ENTER THE NUMBER : '))
scan_config = int(input('which config do yo want for scan? \n 1-Base \n 2-Discovery \n 3-Full and fast \n 4-Host discovery \n 5-system discovery \n PLEASE ENTER THE NUMBER : '))
if type_scanner == 1 and scan_config == 1:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '08b69003-5fc2-4037-a479-93b440211c73',
        config_id= 'd21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663'
    )
elif type_scanner == 1 and scan_config == 2:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '08b69003-5fc2-4037-a479-93b440211c73',
        config_id= '8715c877-47a0-438d-98a3-27c7a6ab2196'
    )
elif type_scanner == 1 and scan_config == 3:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '08b69003-5fc2-4037-a479-93b440211c73',
        config_id= 'daba56c8-73ec-11df-a475-002264764cea'
    )
elif type_scanner == 1 and scan_config == 4:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '08b69003-5fc2-4037-a479-93b440211c73',
        config_id= '2d3f051c-55ba-11e3-bf43-406186ea4fc5'
    )
elif type_scanner == 1 and scan_config == 5:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '08b69003-5fc2-4037-a479-93b440211c73',
        config_id= 'bbca7412-a950-11e3-9109-406186ea4fc5'
    )
##CVE
elif type_scanner == 2 and scan_config == 1:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '6acd0832-df90-11e4-b9d5-28d24461215b',
        config_id= 'd21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663'
    )
elif type_scanner == 2 and scan_config == 2:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '6acd0832-df90-11e4-b9d5-28d24461215b',
        config_id= '8715c877-47a0-438d-98a3-27c7a6ab2196'
    )
elif type_scanner == 2 and scan_config == 3:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '6acd0832-df90-11e4-b9d5-28d24461215b',
        config_id= 'daba56c8-73ec-11df-a475-002264764cea'
    )
elif type_scanner == 2 and scan_config == 4:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '6acd0832-df90-11e4-b9d5-28d24461215b',
        config_id= '2d3f051c-55ba-11e3-bf43-406186ea4fc5'
    )
elif type_scanner == 2 and scan_config == 5:
    res=gmp.create_task(
        name= input(Fore.WHITE+'Enter name of task :'),
        target_id= danial_target_id,
        scanner_id= '6acd0832-df90-11e4-b9d5-28d24461215b',
        config_id= 'bbca7412-a950-11e3-9109-406186ea4fc5'
    )
task_id = res.xpath('@id')[0]
print('--------------------------------------------------------------')
#------------------------------------------------------------------------
# start task
print(Fore.CYAN+'task is running....')
gmp.start_task(task_id)
#-----------------------------------------------------------------------
# get report

a =gmp.get_task(
    task_id= task_id
)

b_xml = ET.tostring(a)
soup = BeautifulSoup(b_xml , 'xml')
show = soup.find('report')
report_idd = show['id']

while True:
    c = gmp.get_report(
        report_id=report_idd
    )
    b_xml = ET.tostring(c)
    soup = BeautifulSoup(b_xml , 'xml')
    showw = soup.find('scan_run_status')
    if showw.text == 'Done':
        pretty_print(c)
        with open(task_id , 'w') as file:           
            file.write(str(b_xml))      #for save in your device
        break