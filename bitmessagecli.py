#!/usr/bin/env python2.7
# Originally created by Adam Melton (Dokument)
# Modified by Scott King (Lvl4Sword)
# Modified for use in the Taskhive project (taskhive.io)
# Distributed under the MIT/X11 software license
# See http://www.opensource.org/licenses/mit-license.php
# https://bitmessage.org/wiki/API_Reference for API documentation

import base64
import ConfigParser
import datetime
import getopt
import hashlib
import imghdr
import json
import ntpath
import os
import random
import signal
import socket
import subprocess
import sys
import time
import xmlrpclib
import string

APPNAME = 'PyBitmessage'
CHARACTERS = string.digits + string.ascii_letters
SECURE_RANDOM = random.SystemRandom()
CONFIG = ConfigParser.RawConfigParser()


class my_bitmessage(object):
    def __init__(self):
        '''
        True = Prompt
        False = Don't Prompt
        '''
        self.api = ''
        self.programDir = os.path.dirname(__file__)
        self.keysPath = self.lookupAppdataFolder()
        self.keysName = self.keysPath + 'keys.dat'
        self.bmActive = False
        self.enableBM = ''
        self.apiImport = False


    # Checks input for exit or quit. Also formats for input, etc
    def userInput(self, message):
        try:
            print('{0}'.format(message))
            uInput = raw_input('> ').strip()
            if uInput.lower() in ['exit', 'x']:
                self.main()
            elif uInput.lower() in ['quit', 'q']:
                print('Shutting down..')
                os.killpg(os.getpgid(self.enableBM.pid), signal.SIGTERM)
                sys.exit(0)
            elif uInput.lower() in ['help', 'h', '?']:
                self.viewHelp()
                self.main()
            else:
                return uInput
        except(EOFError, KeyboardInterrupt):
            # AttributeError is if we didn't get far enough to actually execute Bitmessage
            print('Shutting down..')
            os.killpg(os.getpgid(self.enableBM.pid), signal.SIGTERM)
            sys.exit(0)


    '''
    Begin keys.dat interactions
    gets the appropriate folders for the .dat files depending on the OS.
    Taken from bitmessagemain.py
    '''
    def lookupAppdataFolder(self):
        if sys.platform.startswith('darwin'):
            self.programDir = self.programDir + '/'
            if 'HOME' in os.environ:
                dataFolder = os.path.join(os.environ['HOME'],
                                       'Library/Application support/',
                                       APPNAME) + '/'
            else:
                print('Could not find your home folder.')
                print('Please report this message and your OS X version at:')
                print('https://github.com/RZZT/taskhive-core')
                sys.exit(0)
        elif sys.platform.startswith('win'):
            self.programDir = self.programDir + '\\'
            dataFolder = os.path.join(os.environ['APPDATA'],
                                   APPNAME) + '\\'
        else:
            self.programDir = self.programDir + '/'
            dataFolder = os.path.expanduser(os.path.join('~',
                                        '.config/' + APPNAME + '/'))
        return dataFolder


    def returnApi(self):
        try:
            CONFIG.read(self.keysName)
            apiUsername = CONFIG.get('bitmessagesettings', 'apiusername')
            apiPassword = CONFIG.get('bitmessagesettings', 'apipassword')
            apiInterface = CONFIG.get('bitmessagesettings', 'apiinterface')
            apiPort = CONFIG.getint('bitmessagesettings', 'apiport')
            # Build the api credentials
            print('API data successfully imported')
            return 'http://{0}:{1}@{2}:{3}/'.format(apiUsername,
                                                    apiPassword,
                                                    apiInterface,
                                                    apiPort)
        except ConfigParser.MissingSectionHeaderError:
            print("'bitmessagesettings' header is missing.")
        except ConfigParser.NoOptionError as e:
            print("{0} and possibly others are missing.".format(str(e).split("'")[1]))
        print("I'm going to ask you a series of questions..")
        self.configInit()


    def configInit(self):
        try:
            CONFIG.add_section('bitmessagesettings')
        except ConfigParser.DuplicateSectionError:
            pass
        CONFIG.set('bitmessagesettings', 'port', '8444')
        CONFIG.set('bitmessagesettings', 'apienabled', 'True')
        CONFIG.set('bitmessagesettings', 'settingsversion', '10')
        CONFIG.set('bitmessagesettings', 'apiport', '8444')
        CONFIG.set('bitmessagesettings', 'apiinterface', '127.0.0.1')
        CONFIG.set('bitmessagesettings', 'apiusername',
                   ''.join([SECURE_RANDOM.choice(CHARACTERS) for x in range(0,64)]))
        CONFIG.set('bitmessagesettings', 'apipassword',
                   ''.join([SECURE_RANDOM.choice(CHARACTERS) for x in range(0,64)]))
        CONFIG.set('bitmessagesettings', 'daemon', 'True')
        CONFIG.set('bitmessagesettings', 'timeformat', '%%c')
        CONFIG.set('bitmessagesettings', 'blackwhitelist', 'black')
        CONFIG.set('bitmessagesettings', 'startonlogon', 'False')
        CONFIG.set('bitmessagesettings', 'minimizetotray', 'False')
        CONFIG.set('bitmessagesettings', 'showtraynotifications', 'True')
        CONFIG.set('bitmessagesettings', 'startintray', 'False')
        CONFIG.set('bitmessagesettings', 'sockshostname', 'localhost')
        CONFIG.set('bitmessagesettings', 'socksport', '9050')
        CONFIG.set('bitmessagesettings', 'socksauthentication', 'False')
        CONFIG.set('bitmessagesettings', 'sockslisten', 'False')
        CONFIG.set('bitmessagesettings', 'socksusername', '')
        CONFIG.set('bitmessagesettings', 'sockspassword', '')

        enableTor = self.userInput('\nEnable SOCKS5 Tor connection (Y/n)?').lower()
        if enableTor in ['yes', 'y']:
            CONFIG.set('bitmessagesettings', 'socksproxytype', 'SOCKS5')
            print('Proxy settings are:')
            print('Type: {0}'.format(CONFIG.get('bitmessagesettings', 'socksproxytype')))
            print('Port: {0}'.format(CONFIG.getint('bitmessagesettings', 'socksport')))
            print('Host: localhost'.format(CONFIG.get('bitmessagesettings', 'sockshostname')))

            doubleCheckProxy = self.userInput('Do these need to be changed? (Y/n)').lower()
            if doubleCheckProxy in ['yes', 'y']:
                print('?')
        else:
            CONFIG.set('bitmessagesettings', 'socksproxytype', 'none')

        CONFIG.set('bitmessagesettings', 'keysencrypted', 'False')
        CONFIG.set('bitmessagesettings', 'messagesencrypted', 'False')
        CONFIG.set('bitmessagesettings', 'defaultnoncetrialsperbyte', '1000')
        CONFIG.set('bitmessagesettings', 'defaultpayloadlengthextrabytes', '1000')
        CONFIG.set('bitmessagesettings', 'minimizeonclose', 'False')
        CONFIG.set('bitmessagesettings', 'maxacceptablenoncetrialsperbyte', '20000000000')
        CONFIG.set('bitmessagesettings', 'maxacceptablepayloadlengthextrabytes', '20000000000')
        CONFIG.set('bitmessagesettings', 'userlocale', 'system')
        CONFIG.set('bitmessagesettings', 'useidenticons', 'False')
        CONFIG.set('bitmessagesettings', 'identiconsuffix', '')
        CONFIG.set('bitmessagesettings', 'replybelow', 'False')
        CONFIG.set('bitmessagesettings', 'maxdownloadrate', '0')
        CONFIG.set('bitmessagesettings', 'maxuploadrate', '0')
        CONFIG.set('bitmessagesettings', 'maxoutboundconnections', '8')
        CONFIG.set('bitmessagesettings', 'ttl', '367200')
        CONFIG.set('bitmessagesettings', 'stopresendingafterxdays', '')
        CONFIG.set('bitmessagesettings', 'stopresendingafterxmonths', '')
        CONFIG.set('bitmessagesettings', 'namecoinrpctype', 'namecoind')
        CONFIG.set('bitmessagesettings', 'namecoinrpchost', 'localhost')
        CONFIG.set('bitmessagesettings', 'namecoinrpcuser', '')
        CONFIG.set('bitmessagesettings', 'namecoinrpcpassword', '')
        CONFIG.set('bitmessagesettings', 'namecoinrpcport', '8336')
        CONFIG.set('bitmessagesettings', 'sendoutgoingconnections', 'True')
        CONFIG.set('bitmessagesettings', 'onionhostname', '8444')
        CONFIG.set('bitmessagesettings', 'onionbindip', '127.0.0.1')
        CONFIG.set('bitmessagesettings', 'hidetrayconnectionnotifications', 'False')
        CONFIG.set('bitmessagesettings', 'trayonclose', 'False')
        CONFIG.set('bitmessagesettings', 'willinglysendtomobile', 'False')
        CONFIG.set('bitmessagesettings', 'opencl', 'False')
        if not os.path.isdir(self.keysPath):
            os.mkdir(self.keysPath)
        with open(self.keysName, 'wb') as configfile:
            CONFIG.write(configfile)


    def apiData(self):
        CONFIG.read(self.keysName)
        try:
            CONFIG.getint('bitmessagesettings', 'port')
            CONFIG.getboolean('bitmessagesettings', 'apienabled')
            CONFIG.getint('bitmessagesettings', 'settingsversion')
            CONFIG.getint('bitmessagesettings', 'apiport')
            CONFIG.get('bitmessagesettings', 'apiinterface')
            CONFIG.get('bitmessagesettings', 'apiusername')
            CONFIG.get('bitmessagesettings', 'apipassword')
            CONFIG.getboolean('bitmessagesettings', 'daemon')
            CONFIG.get('bitmessagesettings', 'timeformat')
            CONFIG.get('bitmessagesettings', 'blackwhitelist')
            CONFIG.getboolean('bitmessagesettings', 'startonlogon')
            CONFIG.getboolean('bitmessagesettings', 'minimizetotray')
            CONFIG.getboolean('bitmessagesettings', 'showtraynotifications')
            CONFIG.getboolean('bitmessagesettings', 'startintray')
            CONFIG.get('bitmessagesettings', 'sockshostname')
            CONFIG.getint('bitmessagesettings', 'socksport')
            CONFIG.getboolean('bitmessagesettings', 'socksauthentication')
            CONFIG.getboolean('bitmessagesettings', 'sockslisten')
            CONFIG.get('bitmessagesettings', 'socksusername')
            CONFIG.get('bitmessagesettings', 'sockspassword')
            CONFIG.get('bitmessagesettings', 'socksproxytype')
            CONFIG.get('bitmessagesettings', 'socksproxytype')
            CONFIG.getboolean('bitmessagesettings', 'keysencrypted')
            CONFIG.getboolean('bitmessagesettings', 'messagesencrypted')
            CONFIG.getint('bitmessagesettings', 'defaultnoncetrialsperbyte')
            CONFIG.getint('bitmessagesettings', 'defaultpayloadlengthextrabytes')
            CONFIG.getboolean('bitmessagesettings', 'minimizeonclose')
            CONFIG.getint('bitmessagesettings', 'maxacceptablenoncetrialsperbyte')
            CONFIG.getint('bitmessagesettings', 'maxacceptablepayloadlengthextrabytes')
            CONFIG.get('bitmessagesettings', 'userlocale')
            CONFIG.getboolean('bitmessagesettings', 'useidenticons')
            CONFIG.get('bitmessagesettings', 'identiconsuffix')
            CONFIG.getboolean('bitmessagesettings', 'replybelow')
            CONFIG.getint('bitmessagesettings', 'maxdownloadrate')
            CONFIG.getint('bitmessagesettings', 'maxuploadrate')
            CONFIG.getint('bitmessagesettings', 'maxoutboundconnections')
            CONFIG.getint('bitmessagesettings', 'ttl')
            CONFIG.get('bitmessagesettings', 'stopresendingafterxdays')
            CONFIG.get('bitmessagesettings', 'stopresendingafterxmonths')
            CONFIG.get('bitmessagesettings', 'namecoinrpctype')
            CONFIG.get('bitmessagesettings', 'namecoinrpchost')
            CONFIG.get('bitmessagesettings', 'namecoinrpcuser')
            CONFIG.get('bitmessagesettings', 'namecoinrpcpassword')
            CONFIG.getint('bitmessagesettings', 'namecoinrpcport')
            CONFIG.getboolean('bitmessagesettings', 'sendoutgoingconnections')
            CONFIG.getint('bitmessagesettings', 'onionhostname')
            CONFIG.get('bitmessagesettings', 'onionbindip')
            CONFIG.getboolean('bitmessagesettings', 'hidetrayconnectionnotifications')
            CONFIG.getboolean('bitmessagesettings', 'trayonclose')
            CONFIG.getboolean('bitmessagesettings', 'willinglysendtomobile')
            CONFIG.getboolean('bitmessagesettings', 'opencl')
        except ConfigParser.NoOptionError as e:
            print("{0} and possibly others are missing.".format(str(e).split("'")[1]))
            print("I'm going to ask you a series of questions..")
            self.configInit()
        except ConfigParser.NoSectionError:
            print("No section 'bitmessagesettings'")
            print("I'm going to ask you a series of questions..")
            self.configInit()




#####
# End keys.dat interactions
#####


    # Tests the API connection to bitmessage.
    # Returns true if it is connected.
    def apiTest(self):
        try:
            result = self.api.add(2,3)
            if result == 5:
                return True
            else:
                return False
        except socket.error:
            return False

    # Allows the viewing and modification of keys.dat settings.
    def bmSettings(self):
        # Read the keys.dat
        CONFIG.read(self.keysName)
        startonlogon = CONFIG.getboolean('bitmessagesettings', 'startonlogon')
        minimizetotray = CONFIG.getboolean('bitmessagesettings', 'minimizetotray')
        showtraynotifications = CONFIG.getboolean('bitmessagesettings', 'showtraynotifications')
        startintray = CONFIG.getboolean('bitmessagesettings', 'startintray')
        defaultnoncetrialsperbyte = CONFIG.getint('bitmessagesettings', 'defaultnoncetrialsperbyte')
        defaultpayloadlengthextrabytes = CONFIG.getint('bitmessagesettings', 'defaultpayloadlengthextrabytes')
        daemon = CONFIG.getboolean('bitmessagesettings', 'daemon')
        socksproxytype = CONFIG.get('bitmessagesettings', 'socksproxytype')
        sockshostname = CONFIG.get('bitmessagesettings', 'sockshostname')
        socksport = CONFIG.getint('bitmessagesettings', 'socksport')
        socksauthentication = CONFIG.getboolean('bitmessagesettings', 'socksauthentication')
        socksusername = CONFIG.get('bitmessagesettings', 'socksusername')
        sockspassword = CONFIG.get('bitmessagesettings', 'sockspassword')


        print('-----------------------------------')
        print('|   Current Bitmessage Settings   |')
        print('-----------------------------------')
        print('port = {0}'.format(port))
        print(type(startonlogon))
        print('startonlogon = {0}'.format(startonlogon))
        print('minimizetotray = {0}'.format(minimizetotray))
        print('showtraynotifications = {0}'.format(showtraynotifications))
        print('startintray = {0}'.format(startintray))
        print('defaultnoncetrialsperbyte = {0}'.format(defaultnoncetrialsperbyte))
        print('defaultpayloadlengthextrabytes = {0}'.format(defaultpayloadlengthextrabytes))
        print('daemon = {0}'.format(daemon))
        print('-----------------------------------')
        print('|   Current Connection Settings   |')
        print('-----------------------------------')
        print('socksproxytype = {0}'.format(socksproxytype))
        print('sockshostname = {0}'.format(sockshostname))
        print('socksport = {0}'.format(socksport))
        print('socksauthentication = {0}'.format(socksauthentication))
        print('socksusername = {0}'.format(socksusername))
        print('sockspassword = {0}'.format(sockspassword))

        while True:
            uInput = self.userInput('\nWould you like to modify any of these settings, (Y)/(n)').lower()
            if uInput:
                break

        if uInput in ['yes', 'y']:
            # loops if they mistype the setting name, they can exit the loop with 'exit')
            while True:
                invalidInput = False
                uInput = self.userInput('\nWhat setting would you like to modify?').lower()

                if uInput == 'port':
                    print('Current port number: {0}'.format(port))
                    uInput = self.userInput('\nEnter the new port number.').lower()
                    CONFIG.set('bitmessagesettings', 'port', uInput)

                elif uInput == 'startonlogon':
                    print('Current status: {0}'.format(startonlogon))
                    uInput = self.userInput('\nEnter the new status.').lower()
                    CONFIG.set('bitmessagesettings', 'startonlogon', uInput)

                elif uInput == 'minimizetotray':
                    print('Current status: {0}'.format(minimizetotray))
                    uInput = self.userInput('\nEnter the new status.').lower()
                    CONFIG.set('bitmessagesettings', 'minimizetotray', uInput)

                elif uInput == 'showtraynotifications':
                    print('Current status: {0}'.format(showtraynotifications))
                    uInput = self.userInput('\nEnter the new status.').lower()
                    CONFIG.set('bitmessagesettings', 'showtraynotifications', uInput)

                elif uInput == 'startintray':
                    print('Current status: {0}\n'.format(startintray))
                    uInput = self.userInput('Enter the new status.').lower()
                    CONFIG.set('bitmessagesettings', 'startintray', uInput)

                elif uInput == 'defaultnoncetrialsperbyte':
                    print('Current default nonce trials per byte: {0}'.format(defaultnoncetrialsperbyte))
                    uInput = self.userInput('\nEnter the new defaultnoncetrialsperbyte.').lower()
                    CONFIG.set('bitmessagesettings', 'defaultnoncetrialsperbyte', uInput)

                elif uInput == 'defaultpayloadlengthextrabytes':
                    print('Current default payload length extra bytes: {0}'.format(defaultpayloadlengthextrabytes))
                    uInput = self.userInput('\nEnter the new defaultpayloadlengthextrabytes.').lower()
                    CONFIG.set('bitmessagesettings', 'defaultpayloadlengthextrabytes', uInput)

                elif uInput == 'daemon':
                    print('Current status: {0}'.format(daemon))
                    uInput = self.userInput('\nEnter the new status.').lower()
                    CONFIG.set('bitmessagesettings', 'daemon', uInput)

                elif uInput == 'socksproxytype':
                    print('Current socks proxy type: {0}'.format(socksproxytype))
                    print("Possibilities: 'none', 'SOCKS4a', 'SOCKS5'")
                    uInput = self.userInput('\nEnter the new socksproxytype').lower()
                    CONFIG.set('bitmessagesettings', 'socksproxytype', uInput)

                elif uInput == 'sockshostname':
                    print('Current socks host name: {0}'.format(sockshostname))
                    uInput = self.userInput('\nEnter the new sockshostname').lower()
                    CONFIG.set('bitmessagesettings', 'sockshostname', uInput)

                elif uInput == 'socksport':
                    print('Current socks port number: {0}'.format(socksport))
                    uInput = self.userInput('\nEnter the new socksport').lower()
                    CONFIG.set('bitmessagesettings', 'socksport', uInput)

                elif uInput == 'socksauthentication':
                    print('Current status: {0}'.format(socksauthentication))
                    uInput = self.userInput('\nEnter the new status').lower()
                    CONFIG.set('bitmessagesettings', 'socksauthentication', uInput)

                elif uInput == 'socksusername':
                    print('Current socks username: {0}'.format(socksusername))
                    uInput = self.userInput('\nEnter the new socksusername')
                    CONFIG.set('bitmessagesettings', 'socksusername', uInput)

                elif uInput == 'sockspassword':
                    print('Current socks password: {0}'.format(sockspassword))
                    uInput = self.userInput('\nEnter the new sockspassword')
                    CONFIG.set('bitmessagesettings', 'sockspassword', uInput)
                else:
                    print('Invalid input. Please try again')
                    invalidInput = True

                # don't prompt if they made a mistake. 
                if not invalidInput:
                    uInput = self.userInput('\nWould you like to change another setting, (Y)/(n)').lower()

                    if uInput not in ['yes', 'y']:
                        with open(self.keysName, 'wb') as configfile:
                            CONFIG.write(configfile)
                        print('Changes made')
                        break
        self.main()


    def validAddress(self, address):
        try:
            address_information = json.loads(self.api.decodeAddress(address))
            if address_information.get('status') == 'success':
                return True
            else:
                return False
        except AttributeError:
            return False

    def getAddress(self, passphrase, vNumber, sNumber):
        # passphrase must be encoded
        passphrase = base64.b64encode(passphrase)
        return self.api.getDeterministicAddress(passphrase,vNumber,sNumber)


    def subscribe(self):
        while True:
            address = self.userInput('\nAddress you would like to subscribe to:')
            if self.validAddress(address):
                break
            else:
                print('Not a valid address, please try again.')
        while True:
            label = self.userInput('\nEnter a label for this address:')
            label = base64.b64encode(label)
            break
        self.api.addSubscription(address, label)
        print('You are now subscribed to: {0}'.format(address))


    def unsubscribe(self):
        while True:
            address = self.userInput('\nEnter the address to unsubscribe from:')
            if self.validAddress(address):
                break
        while True:
            uInput = self.userInput('\nAre you sure, (Y)/(n)').lower()
            if uInput in ['yes', 'y']:
                self.api.deleteSubscription(address)
                print('You are now unsubscribed from: ' + address)
            else:
                print("You weren't unsubscribed from anything.")
            break


    def listSubscriptions(self):
        total_subscriptions = json.loads(self.api.listSubscriptions())
        print('-------------------------------------')
        for each in total_subscriptions['subscriptions']:
            print('Label: {0}'.format(base64.b64decode(each['label'])))
            print('Address: {0}'.format(each['address']))
            print('Enabled: {0}'.format(each['enabled']))
            print('-------------------------------------')
        self.main()


    def createChan(self):
        password = self.userInput('\nEnter channel name:')
        password = base64.b64encode(password)
        print('Channel password: ' + self.api.createChan(password))
        self.main()


    def joinChan(self):
        while True:
            address = self.userInput('\nEnter Channel Address:')
            if self.validAddress(address):
                break
        while True:
            password = self.userInput('\nEnter Channel Name:')
            if password:
                break
        password = base64.b64encode(password)

        joiningChannel = self.api.joinChan(password, address)
        if joiningChannel == 'success':
            print('Successfully joined {0}'.format(address))
        elif joiningChannel.endswith('list index out of range'):
            print("You're already in that channel")
        self.main()


    def leaveChan(self):
        while True:
            address = self.userInput('\nEnter Channel Address or Label:')
            if self.validAddress(address):
                break
            else:
                jsonAddresses = json.loads(self.api.listAddresses())
                # Number of addresses
                numAddresses = len(jsonAddresses['addresses'])
                # processes all of the addresses and lists them out
                for addNum in range (0, numAddresses):
                    label = jsonAddresses['addresses'][addNum]['label']
                    jsonAddress = jsonAddresses['addresses'][addNum]['address']
                    if '[chan] {0}'.format(address) == label:
                        address = jsonAddress
                        found = True
                        break
            if found:
                break
        leavingChannel = self.api.leaveChan(address)
        if leavingChannel == 'success':
            print('Successfully left {0}'.format(address))
        else:
            print(leavingChannel)
        self.main()


    # Lists all of the addresses and their info
    def listAdd(self):
        jsonListAddresses = json.loads(self.api.listAddresses())
        # Number of addresses
        jsonAddresses = jsonListAddresses['addresses']
        numAddresses = len(jsonAddresses)

        if not jsonAddresses:
            print('You have no addresses!')
        else:
            print('-------------------------------------')
            for each in jsonAddresses:
                print('Label: {0}'.format(each['label']))
                print('Address: {0}'.format(each['address']))
                print('Stream: {0}'.format(each['stream']))
                print('Enabled: {0}'.format(each['enabled']))
                print('-------------------------------------')
        self.main()

    # Generate address
    def genAdd(self, lbl, deterministic, passphrase, numOfAdd, addVNum, streamNum, ripe):
        # Generates a new address with the user defined label. non-deterministic
        if not deterministic:
            addressLabel = base64.b64encode(lbl)
            generatedAddress = self.api.createRandomAddress(addressLabel)
            return generatedAddress
        # Generates a new deterministic address with the user inputs
        elif deterministic:
            passphrase = base64.b64encode(passphrase)
            generatedAddress = self.api.createDeterministicAddresses(passphrase, numOfAdd, addVNum, streamNum, ripe)
            return generatedAddress
        else:
            return 'Entry Error'
        self.main()


    def deleteAddress(self):
        jsonListAddresses = json.loads(self.api.listAddresses())
        # Number of addresses
        jsonAddresses = jsonListAddresses['addresses']
        numAddresses = len(jsonAddresses)

        if not jsonAddresses:
            print('You have no addresses!')
        else:
            while True:
                address = self.userInput('\nEnter Address or Label you wish to delete:')
                if self.validAddress(address):
                    break
                else:
                    jsonAddresses = json.loads(self.api.listAddresses())
                    # Number of addresses
                    numAddresses = len(jsonAddresses['addresses'])
                    # processes all of the addresses and lists them out
                    for addNum in range (0, numAddresses):
                        label = jsonAddresses['addresses'][addNum]['label']
                        jsonAddress = jsonAddresses['addresses'][addNum]['address']
                        if '{0}'.format(address) == label:
                            address = jsonAddress
                            found = True
                            break
                if found:
                    self.api.deleteAddress(address)
                    print('{0} has been deleted!'.format(address))
                    break
        self.main()        


    # Allows attachments and messages/broadcats to be saved
    def saveFile(self, fileName, fileData):
        # This section finds all invalid characters and replaces them with ~
        fileNameReplacements = {"/":"~",
                                "\\":"~",
                                ":":"~",
                                "*":"~",
                                "?":"~",
                                "'":"~",
                                "<":"~",
                                ">":"~",
                                "|":"~"}
        for keys, values in fileNameReplacements.iteritems():
            fileName = fileName.replace(keys, values)

        while True:
            directory = self.userInput('Where would you like to save the attachment?: ')
            if not os.path.exists(directory):
                print("That directory doesn't exist.")
            else:
                if sys.platform.startswith('win'):
                    if not directory.endswith('\\'):
                        directory = directory + '\\'
                else:
                    if not directory.endswith('/'):
                        directory = directory + '/'

                filePath = directory + fileName

                # Begin saving to file
                try:
                    with open(filePath, 'wb+') as f:
                        f.write(base64.b64decode(fileData))
                except IOError:
                    print("Failed to save the attachment. Choose another directory")
                else:
                    print('Successfully saved {0}'.format(filePath))
                    break


    # Allows users to attach a file to their message or broadcast
    def attachment(self):
        theAttachmentS = ''

        while True:
            isImage = False
            theAttachment = ''

            filePath = self.userInput('\nPlease enter the path to the attachment')

            try:
                with open(filePath):
                    break
            except IOError:
                print('{0} was not found on your filesystem or can not be opened.'.format(filePath))

        while True:
            invSize = os.path.getsize(filePath)
            # Converts to kilobytes
            invSize = (invSize / 1024.0)
            # Rounds to two decimal places
            round(invSize, 2)

            # If over 200KB
            if invSize > 200.0:
                print('WARNING: The maximum message size including attachments, body, and headers is 256KB.')
                print("If you reach over this limit, your message won't send.")
                print("Your current attachment is {0}".format(invSize))
                uInput = self.userInput('\nAre you sure you still want to attach it, (Y)/(n)').lower()

                if uInput not in ['yes', 'y']:
                    print('Attachment discarded.')
                    return ''

            # If larger than 256KB, discard
            if invSize > 256.0:
                print('Attachment too big, maximum allowed message size is 256KB')
                return ''

            break

        # Gets the length of the filepath excluding the filename
        pathLen = len(str(ntpath.basename(filePath)))
        # reads the filename
        fileName = filePath[(len(str(filePath)) - pathLen):]

        # Tests if it is an image file
        filetype = imghdr.what(filePath)
        if filetype is not None:
            print('------------------------------------------')
            print('     Attachment detected as an Image.')
            print('<img> tags will be automatically included.')
            print('------------------------------------------')
            isImage = True
            time.sleep(3)
        # Alert the user that the encoding process may take some time
        print('Encoding attachment, please wait ...')
        # Begin the actual encoding
        with open(filePath, 'rb') as f:
            # Reads files up to 256KB
            data = f.read(262144)
            data = base64.b64encode(data)

        # If it is an image, include image tags in the message
        if isImage:
            theAttachment = '<!-- Note: Base64 encoded image attachment below. -->\n\n'
            theAttachment += 'Filename:{0}\n'.format(fileName)
            theAttachment += 'Filesize:{0}KB\n'.format(invSize)
            theAttachment += 'Encoding:base64\n\n'
            theAttachment += '<center>\n'
            theAttachment += "<img alt = \"{0}\" src='data:image/{0};base64, {1}' />\n".format(fileName, data)
            theAttachment += '</center>'
        # Else it is not an image so do not include the embedded image code.
        else:
            theAttachment = '<!-- Note: Base64 encoded file attachment below. -->\n\n'
            theAttachment += 'Filename:{0}\n'.format(fileName)
            theAttachment += 'Filesize:{0}KB\n'.format(invSize)
            theAttachment += 'Encoding:base64\n\n'
            theAttachment += '<center>\n'
            theAttachment += "<img alt = \"{0}\" src='data:file/{0};base64, {1}' />\n".format(fileName, data)
            theAttachment += '</center>'
        theAttachmentS = theAttachmentS + theAttachment
        return theAttachmentS


    # With no arguments sent, sendMsg fills in the blanks
    # subject and message must be encoded before they are passed
    def sendMsg(self, toAddress, fromAddress, subject, message):
        jsonAddresses = json.loads(self.api.listAddresses().encode('UTF-8'))
        # Number of addresses
        numAddresses = len(jsonAddresses['addresses'])

        if not self.validAddress(toAddress):
            found = False
            while True:
                toAddress = self.userInput('\nWhat is the To Address?')
                if self.validAddress(toAddress):
                    break
                else:
                    for addNum in range (0, numAddresses):
                        label = jsonAddresses['addresses'][addNum]['label']
                        address = jsonAddresses['addresses'][addNum]['address']
                        if label.startswith('[chan] '):
                            label = label.split('[chan] ')[1]
                        # address entered was a label and is found
                        elif toAddress == label:
                            found = True
                            toAddress = address
                            break
                    if not found:
                        print('Invalid Address. Please try again.')
                    else:
                        # Address was found
                        break

        if not self.validAddress(fromAddress):
            # Ask what address to send from if multiple addresses
            if numAddresses > 1:
                found = False
                while True:
                    fromAddress = self.userInput('\nEnter an Address or Address Label to send from')

                    if not self.validAddress(fromAddress):
                        # processes all of the addresses
                        for addNum in range (0, numAddresses):
                            label = jsonAddresses['addresses'][addNum]['label']
                            address = jsonAddresses['addresses'][addNum]['address']
                            if label.startswith('[chan] '):
                                label = label.split('[chan] ')[1]
                            # address entered was a label and is found
                            if fromAddress == label:
                                found = True
                                fromAddress = address
                                break
                        if not found:
                            print('Invalid Address. Please try again.')
                    else:
                        for addNum in range (0, numAddresses):
                            address = jsonAddresses['addresses'][addNum]['address']
                            # address entered was found in our address book
                            if fromAddress == address:
                                found = True
                                break
                        if not found:
                            print('The address entered is not one of yours. Please try again.')
                        else:
                            # Address was found
                            break
                    if found:
                        break

            # Only one address in address book
            else:
                print('Using the only address in the addressbook to send from.')
                fromAddress = jsonAddresses['addresses'][0]['address']

        if subject == '':
            subject = self.userInput('\nEnter your subject')
            subject = base64.b64encode(subject)

        if message == '':
            message = self.userInput('\nEnter your message.')

        uInput = self.userInput('\nWould you like to add an attachment, (Y)/(n)').lower()

        if uInput in ['yes', 'y']:
            message = '{0}\n\n{1}'.format(message, self.attachment())
        message = base64.b64encode(message)

        ackData = self.api.sendMessage(toAddress, fromAddress, subject, message)
        sendMessage = self.api.getStatus(ackData)
        # TODO - There are more statuses that should be paid attention to
        if sendMessage == 'doingmsgpow':
            print('Doing POW, will send soon.')
        else:
            print(sendMessage)


    # sends a broadcast
    def sendBrd(self, fromAddress, subject, message):
        if fromAddress == '':
            jsonAddresses = json.loads(self.api.listAddresses().encode('UTF-8'))
            # Number of addresses
            numAddresses = len(jsonAddresses['addresses'])

            # Ask what address to send from if multiple addresses
            if numAddresses > 1:
                found = False
                while True:
                    fromAddress = self.userInput('\nEnter an Address or Address Label to send from')

                    if not self.validAddress(fromAddress):
                        # processes all of the addresses
                        for addNum in range (0, numAddresses):
                            label = jsonAddresses['addresses'][addNum]['label']
                            address = jsonAddresses['addresses'][addNum]['address']
                            if label.startswith('[chan] '):
                                label = label.split('[chan] ')[1]
                            # address entered was a label and is found
                            if fromAddress == label:
                                found = True
                                fromAddress = address
                                break
                        if not found:
                            print('Invalid Address. Please try again.')
                    else:
                        for addNum in range (0, numAddresses):
                            address = jsonAddresses['addresses'][addNum]['address']
                            # address entered was found in our address book
                            if fromAddress == address:
                                found = True
                                break
                        if not found:
                            print('The address entered is not one of yours. Please try again.')
                        else:
                            # Address was found
                            break

                    if found:
                        break

            # Only one address in address book
            else:
                print('Using the only address in the addressbook to send from.')
                fromAddress = jsonAddresses['addresses'][0]['address']

        if subject == '':
                subject = self.userInput('\nEnter your Subject.')
                subject = base64.b64encode(subject)
        if message == '':
                message = self.userInput('\nEnter your Message.')

        uInput = self.userInput('\nWould you like to add an attachment, (Y)/(n)').lower()
        if uInput in ['yes', 'y']:
            message = message + '\n\n' + self.attachment()
        message = base64.b64encode(message)

        ackData = self.api.sendBroadcast(fromAddress, subject, message)
        sendMessage = self.api.getStatus(ackData)
        # TODO - There are more statuses that should be paid attention to
        if sendMessage == 'broadcastqueued':
            print('Broadcast is now in the queue')
        else:
            print(sendMessage)


    # Lists the messages by: Message Number, To Address Label,
    # From Address Label, Subject, Received Time
    def inbox(self, unreadOnly):
        inboxMessages = json.loads(self.api.getAllInboxMessages())
        numMessages = len(inboxMessages['inboxMessages'])

        messagesPrinted = 0
        messagesUnread = 0
        # processes all of the messages in the inbox
        for msgNum in range (0, numMessages):
            message = inboxMessages['inboxMessages'][msgNum]
            # if we are displaying all messages or
            # if this message is unread then display it
            if not unreadOnly or not message['read']:
                print('-----------------------------------')
                # Message Number
                print('Message Number: {0}'.format(msgNum))
                # Get the to address
                print('To: {0}'.format(message['toAddress']))
                # Get the from address
                print('From: {0}'.format(message['fromAddress']))
                # Get the subject
                print('Subject: {0}'.format(base64.b64decode(message['subject'])))
                print('Received: {0}'.format(datetime.datetime.fromtimestamp(float(message['receivedTime'])).strftime('%Y-%m-%d %H:%M:%S')))
                messagesPrinted += 1
                if not message['read']:
                    messagesUnread += 1

            # TODO - why use the %?
            if messagesPrinted % 20 == 0 and messagesPrinted != 0:
                uInput = self.userInput('\nPress Enter to continue').lower()

        print('-----------------------------------')
        print('There are %d unread messages of %d messages in the inbox.' % (messagesUnread, numMessages))
        print('-----------------------------------')


    def outbox(self):
        outboxMessages = json.loads(self.api.getAllSentMessages())
        numMessages = len(outboxMessages['sentMessages'])
        # processes all of the messages in the outbox
        msgNum = 0
        for each in outboxMessages['sentMessages']:
            print('-----------------------------------')
            # Message Number
            print('Message Number: {0}'.format(msgNum))
            # Get the to address
            print('To: {0}'.format(each['toAddress']))
            # Get the from address
            print('From: {0}'.format(each['fromAddress']))
            # Get the subject
            print('Subject: {0}'.format(base64.b64decode(each['subject'])))
            # Get the subject
            print('Status: {0}'.format(each['status']))

            print('Last Action Time: {0}'.format(datetime.datetime.fromtimestamp(float(each['lastActionTime'])).strftime('%Y-%m-%d %H:%M:%S')))
            msgNum += 1

        print('-----------------------------------')
        print('There are {0} messages in the outbox.'.format(numMessages))
        print('-----------------------------------')


    # Opens a sent message for reading
    def readSentMsg(self, msgNum):
        outboxMessages = json.loads(self.api.getAllSentMessages())
        numMessages = len(outboxMessages['sentMessages'])
    
        if msgNum >= numMessages:
            print('Invalid Message Number')
            self.main()

        ####
        # Begin attachment detection
        ####
        message = base64.b64decode(outboxMessages['sentMessages'][msgNum]['message'])

        # Allows multiple messages to be downloaded/saved
        while True:
            # Found this text in the message, there is probably an attachment
            if ';base64,' in message:
                # Finds the attachment position
                attPos= message.index(';base64,')
                # Finds the end of the attachment
                attEndPos = message.index("' />")

                # We can get the filename too
                if "alt = '" in message:
                    # Finds position of the filename
                    fnPos = message.index('alt = "')
                    # Finds the end position
                    fnEndPos = message.index('" src=')

                    fileName = message[fnPos+7:fnEndPos]
                else:
                    fnPos = attPos
                    fileName = 'Attachment'

                uInput = self.userInput('\nAttachment Detected. Would you like to save the attachment, (Y)/(n)').lower()
                if uInput in ['yes', 'y']:
                    attachment = message[attPos+9:attEndPos]
                    self.saveFile(fileName,attachment)

                message = message[:fnPos] + '~<Attachment data removed for easier viewing>~' + message[(attEndPos+4):]
            else:
                break

        # Get the to address
        print('To: {0}'.format(outboxMessages['sentMessages'][msgNum]['toAddress']))
        # Get the from address
        print('From: {0}'.format(outboxMessages['sentMessages'][msgNum]['fromAddress']))
        # Get the subject
        print('Subject: {0}'.format(base64.b64decode(outboxMessages['sentMessages'][msgNum]['subject'])))
        #Get the status
        print('Status: {0}'.format(outboxMessages['sentMessages'][msgNum]['status']))
        print('Last Action Time: {0}'.format(datetime.datetime.fromtimestamp(float(outboxMessages['sentMessages'][msgNum]['lastActionTime'])).strftime('%Y-%m-%d %H:%M:%S')))
        print('Message: {0}'.format(message))


    # Opens a message for reading
    def readMsg(self, msgNum):
        inboxMessages = json.loads(self.api.getAllInboxMessages())
        numMessages = len(inboxMessages['inboxMessages'])

        if msgNum >= numMessages:
            print('Invalid Message Number.')
            self.main()

        ####
        # Begin attachment detection
        ####
        message = base64.b64decode(inboxMessages['inboxMessages'][msgNum]['message'])

        # Allows multiple messages to be downloaded/saved
        while True:
            # Found this text in the message, there is probably an attachment
            if ';base64,' in message:
                # Finds the attachment position
                attPos= message.index(';base64,')
                # Finds the end of the attachment
                attEndPos = message.index("' />")

                # We can get the filename too
                if 'alt = "' in message:
                    # Finds position of the filename
                    fnPos = message.index('alt = "')
                    # Finds the end position
                    fnEndPos = message.index('" src=')
                    fileName = message[fnPos+7:fnEndPos]
                else:
                    fnPos = attPos
                    fileName = 'Attachment'

                uInput = self.userInput('\nAttachment Detected. Would you like to save the attachment, (Y)/(n)').lower()
                if uInput in ['yes', 'y']:
                    attachment = message[attPos+9:attEndPos]
                    self.saveFile(fileName,attachment)

                message = message[:fnPos] + '~<Attachment data removed for easier viewing>~' + message[(attEndPos+4):]

            else:
                break
####
#End attachment Detection
####

        # Get the to address
        print('To: {0}'.format(inboxMessages['inboxMessages'][msgNum]['toAddress']))
        # Get the from address
        print('From: {0}'.format(inboxMessages['inboxMessages'][msgNum]['fromAddress']))
        # Get the subject
        print('Subject: {0}'.format(base64.b64decode(inboxMessages['inboxMessages'][msgNum]['subject'])))
        print('Received: {0}'.format(datetime.datetime.fromtimestamp(float(inboxMessages['inboxMessages'][msgNum]['receivedTime'])).strftime('%Y-%m-%d %H:%M:%S')))
        print('Message: {0}'.format(message))
        return inboxMessages['inboxMessages'][msgNum]['msgid']


    # Allows you to reply to the message you are currently on.
    # Saves typing in the addresses and subject.
    def replyMsg(msgNum,forwardORreply):
        # makes it lowercase
        forwardORreply = forwardORreply.lower()
        inboxMessages = json.loads(self.api.getAllInboxMessages())

        # Address it was sent To, now the From address
        fromAdd = inboxMessages['inboxMessages'][msgNum]['toAddress']
        # Message that you are replying to
        message = base64.b64decode(inboxMessages['inboxMessages'][msgNum]['message'])

        subject = inboxMessages['inboxMessages'][msgNum]['subject']
        subject = base64.b64decode(subject)

        if forwardORreply == 'reply':
            # Address it was From, now the To address
            toAdd = inboxMessages['inboxMessages'][msgNum]['fromAddress']
            subject = 'Re: {0}'.format(subject)

        elif forwardORreply == 'forward':
            subject = 'Fwd: {0}'.format(subject)

            while True:
                toAdd = self.userInput('\nWhat is the To Address?')
                if not self.validAddress(toAdd):
                    print('Invalid Address. Please try again.')
                else:
                    break
        else:
            print('Invalid Selection. Reply or Forward only')
            return

        subject = base64.b64encode(subject)

        newMessage = self.userInput('\nEnter your Message.')

        uInput = self.userInput('\nWould you like to add an attachment, (Y)/(n)').lower()
        if uInput in ['yes', 'y']:
            newMessage = newMessage + '\n\n' + self.attachment()

        newMessage = newMessage + '\n\n' + '-' * 55 + '\n'
        newMessage = newMessage + message
        newMessage = base64.b64encode(newMessage)

        self.sendMsg(toAdd, fromAdd, subject, newMessage)


    def delMsg(self, msgNum):
        # Deletes a specified message from the inbox
        inboxMessages = json.loads(self.api.getAllInboxMessages())
        # gets the message ID via the message index number
        msgId = inboxMessages['inboxMessages'][int(msgNum)]['msgid']
        msgAck = self.api.trashMessage(msgId)
        return msgAck


    # Deletes a specified message from the outbox
    def delSentMsg(self, msgNum):
        outboxMessages = json.loads(self.api.getAllSentMessages())
        # gets the message ID via the message index number
        msgId = outboxMessages['sentMessages'][int(msgNum)]['msgid']
        msgAck = self.api.trashSentMessage(msgId)
        return msgAck


    def listAddressBookEntries(self):
        response = self.api.listAddressBookEntries()
        if 'API Error' in response:
            return self.getAPIErrorCode(response)
        addressBook = json.loads(response)
        if addressBook['addresses']:
            print('-------------------------------------')
            for each in addressBook['addresses']:
                print('Label: {0}'.format(base64.b64decode(each['label'])))
                print('Address: {0}'.format(each['address']))
                print('-------------------------------------')
        else:
            print('No addresses found in address book.')


    def addAddressToAddressBook(self, address, label):
        response = self.api.addAddressBookEntry(address, base64.b64encode(label))
        if 'API Error' in response:
            return self.getAPIErrorCode(response)


    def deleteAddressFromAddressBook(self, address):
        response = self.api.deleteAddressBookEntry(address)
        if 'API Error' in response:
            return self.getAPIErrorCode(response)


    def getAPIErrorCode(self, response):
        if 'API Error' in response:
            # if we got an API error return the number by getting the number
            # after the second space and removing the trailing colon
            return int(response.split()[2][:-1])


    def markMessageRead(self, messageID):
        response = self.api.getInboxMessageByID(messageID, True)
        if 'API Error' in response:
            return self.getAPIErrorCode(response)


    def markMessageUnread(self, messageID):
        response = self.api.getInboxMessageByID(messageID, False)
        if 'API Error' in response:
            return self.getAPIErrorCode(response)


    def markAllMessagesRead(self):
        inboxMessages = json.loads(self.api.getAllInboxMessages())['inboxMessages']
        for message in inboxMessages:
            if not message['read']:
                markMessageRead(message['msgid'])


    def markAllMessagesUnread(self):
        inboxMessages = json.loads(self.api.getAllInboxMessages())['inboxMessages']
        for message in inboxMessages:
            if message['read']:
                markMessageUnread(message['msgid'])


    def deleteInboxMessages(self):
        inboxMessages = json.loads(self.api.getAllInboxMessages())
        numMessages = len(inboxMessages['inboxMessages'])

        while True:
            msgNum = self.userInput('\nEnter the number of the message you wish to delete or (A)ll to empty the inbox.').lower()
            try:
                if msgNum in ['all', 'a'] or int(msgNum) == numMessages:
                    break
                elif int(msgNum) >= numMessages:
                    print('Invalid Message Number')
                elif int(msgNum) <= numMessages:
                    break
                else:
                    print('Invalid input')
            except ValueError:
                print('Invalid input')

        # Prevent accidental deletion
        uInput = self.userInput('\nAre you sure, (Y)/(n)').lower()

        if uInput in ['yes', 'y']:
            if msgNum in ['all', 'a'] or int(msgNum) == numMessages:
                # Processes all of the messages in the inbox
                for msgNum in range (0, numMessages):
                    print('Deleting message {0} of {1}'.format(msgNum+1, numMessages))
                    self.delMsg(0)
                print('Inbox is empty.')
            else:
                self.delMsg(int(msgNum))
            print('Notice: Message numbers may have changed.')


    def addInfo(self):
        while True:
            address = self.userInput('\nEnter the Bitmessage Address:')
            try:
                address_information = json.loads(str(self.api.decodeAddress(address)))
                if address_information['status'] == 'success':
                    print('Address Version: {0}'.format(address_information['addressVersion']))
                    print('Stream Number: {0}'.format(address_information['streamNumber']))
                    break
                else:
                    print('Invalid address!')
            except AttributeError:
                print('Invalid address!')


    def sendSomething(self):
        while True:
            uInput = self.userInput('\nWould you like to send a (M)essage or (B)roadcast?').lower()
            if uInput in ['message', 'm', 'broadcast', 'b']:
                break
            else:
                print('Invald input')
        if uInput in ['message', 'm']:
            self.sendMsg('','','','')
        elif uInput in ['broadcast', 'b']:
            self.sendBrd('','','')


    def viewHelp(self):
        print('-----------------------------------------------------------------------')
        print('|                https://github.com/RZZT/taskhive-core                |')
        print('|---------------------------------------------------------------------|')
        print('|   Command               | Description                               |')
        print('|-------------------------|-------------------------------------------|')
        print('| (h)elp or ?             | This help file                            |')
        print('| apiTest                 | Tests the API                             |')
        print('| addInfo                 | Returns address information (If valid)    |')
        print('| bmSettings              | BitMessage settings                       |')
        print('| e(x)it                  | Use anytime to return to main menu        |')
        print('| (q)uit                  | Quits the program                         |')
        print('|-------------------------|-------------------------------------------|')
        print('| listAddresses           | Lists all of the users addresses          |')
        print('| generateAddress         | Generates a new address                   |')
        print('| getAddress              | Get deterministic address from passphrase |')
        print('| deleteAddress           | Deletes a generated address               |')
        print('|-------------------------|-------------------------------------------|')
        print('| listAddressBookEntries  | Lists entries from the Address Book       |')
        print('| addAddressBookEntry     | Add address to the Address Book           |')
        print('| deleteAddressBookEntry  | Deletes address from the Address Book     |')
        print('|-------------------------|-------------------------------------------|')
        print('| listSubscriptions       | Lists all addresses subscribed to         |')
        print('| subscribe               | Subscribes to an address                  |')
        print('| unsubscribe             | Unsubscribes from an address              |')
        print('|-------------------------|-------------------------------------------|')
        print('| create                  | Creates a channel                         |')
        print('| join                    | Joins a channel                           |')
        print('| leave                   | Leaves a channel                          |')
        print('|-------------------------|-------------------------------------------|')
        print('| inbox                   | Lists message information for the inbox   |')
        print('| outbox                  | Lists message information for the outbox  |')
        print('| send                    | Send a new message or broadcast           |')
        print('| unread                  | Lists all unread inbox messages           |')
        print('| read                    | Reads a message from the inbox or outbox  |')
        print('| save                    | Saves message to text file                |')
        print('| delete                  | Deletes a message or all messages         |')
        print('-----------------------------------------------------------------------')


    # Main user menu
    def UI(self, usrInput):
        # tests the API Connection.
        if usrInput in ['apitest']:
            if self.apiTest():
                print('API connection test has: PASSED')
            else:
                print('API connection test has: FAILED')

        elif usrInput in ['addinfo']:
            self.addInfo()

        # tests the API Connection.
        elif usrInput in ['bmsettings']:
            self.bmSettings()

        # Lists all of the identities in the addressbook
        elif usrInput in ['listaddresses']:
            self.listAdd()

        # Generates a new address
        elif usrInput in ['generateaddress']:
            while True:
                uInput = self.userInput('\nWould you like to create a (D)eterministic or (R)andom address?').lower()
                if uInput in ['deterministic', 'd', 'random', 'r']:
                    break
                else:
                    print('Invalid input')

            # Creates a deterministic address
            if uInput in ['deterministic', 'd']:
                deterministic = True

                lbl = self.userInput('\nLabel the new address:')
                passphrase = self.userInput('\nEnter the Passphrase.')

                while True:
                    try:
                        numOfAdd = int(self.userInput('\nHow many addresses would you like to generate?').lower())
                    except ValueError:
                        print("That's not a whole number.")
                    if numOfAdd <= 0:
                        print('How were you expecting that to work?')
                    elif numOfAdd >= 1000:
                        print('Limit of 999 addresses generated at once.')
                    else:
                        break
                addVNum = 3
                streamNum = 1
                isRipe = self.userInput('\nShorten the address, (Y)/(n)').lower()
                print('Generating, please wait...')

                if isRipe in ['yes', 'y']:
                    ripe = True
                else:
                    ripe = False
                genAddrs = self.genAdd(lbl,deterministic, passphrase, numOfAdd, addVNum, streamNum, ripe)
                jsonAddresses = json.loads(genAddrs)

                if numOfAdd >= 2:
                    print('Addresses generated: ')
                elif numOfAdd == 1:
                    print('Address generated: ')
                for each in jsonAddresses['addresses']:
                    print(each)

            # Creates a random address with user-defined label
            elif uInput in ['random', 'r']:
                deterministic = False
                lbl = self.userInput('\nEnter the label for the new address.')
                print('Generated Address: {0}'.format(self.genAdd(lbl, deterministic, '', '', '', '', '')))

        # Gets the address for/from a passphrase
        elif usrInput in ['getaddress']:
            phrase = self.userInput('\nEnter the address passphrase.')
            address = self.getAddress(phrase,4,1)
            print('Address: {0}'.format(address))

        elif usrInput in ['deleteaddress']:
            self.deleteAddress()

        # Subsribe to an address
        elif usrInput in ['subscribe']:
            self.subscribe()

        # Unsubscribe from an address
        elif usrInput in ['unsubscribe']:
            self.unsubscribe()

        # Unsubscribe from an address
        elif usrInput in ['listsubscriptions']:
            self.listSubscriptions()

        elif usrInput in ['create']:
            self.createChan()

        elif usrInput in ['join']:
            self.joinChan()

        elif usrInput in ['leave']:
            self.leaveChan()

        elif usrInput in ['inbox']:
            self.inbox(False)

        elif usrInput in ['unread']:
            self.inbox(True)

        elif usrInput in ['outbox']:
            self.outbox()

        # Sends a message or broadcast
        elif usrInput in ['send']:
            self.sendSomething()

        # Opens a message from the inbox for viewing.
        elif usrInput in ['read']:
            while True:
                uInput = self.userInput('\nWould you like to read a message from the (I)nbox or (O)utbox?').lower()
                if uInput in ['inbox', 'outbox', 'i', 'o']:
                    break
            try:
                msgNum = int(self.userInput('\nWhat is the number of the message you wish to open?').lower())
            except ValueError:
                print("That's not a whole number")

            if uInput in ['inbox', 'i']:
                print('Loading...')
                messageID = self.readMsg(msgNum)

                uInput = self.userInput('\nWould you like to keep this message unread, (Y)/(n)').lower()

                if uInput not in ['yes', 'y']:
                    self.markMessageRead(messageID)

                while True:
                    uInput = self.userInput('\nWould you like to (D)elete, (F)orward or (R)eply?').lower()
                    if uInput in ['reply','r','forward','f','delete','d','forward','f','reply','r']:
                        break
                    else:
                        print('Invalid input')

                if uInput in ['reply', 'r']:
                    print('Loading...')
                    print('')
                    self.replyMsg(msgNum,'reply')

                elif uInput in ['forward', 'f']:
                    print('Loading...')
                    print('')
                    self.replyMsg(msgNum,'forward')

                elif uInput in ['delete', 'd']:
                    # Prevent accidental deletion
                    uInput = self.userInput('\nAre you sure, (Y)/(n)').lower()

                    if uInput in ['yes', 'y']:
                        self.delMsg(msgNum)
                        print('Message Deleted.')
 
            elif uInput in ['outbox', 'o']:
                self.readSentMsg(msgNum)
                # Gives the user the option to delete the message
                uInput = self.userInput('\nWould you like to Delete this message, (Y)/(n)').lower()

                if uInput in ['yes', 'y']:
                    # Prevent accidental deletion
                    uInput = self.userInput('\nAre you sure, (Y)/(n)').lower()

                    if uInput in ['yes', 'y']:
                        self.delSentMsg(msgNum)
                        print('Message Deleted.')

        elif usrInput in ['save']:
            while True:
                uInput = self.userInput('\nWould you like to save a message from the (I)nbox or (O)utbox?').lower()
                if uInput in ['inbox', 'outbox', 'i', 'o']:
                    break
                else:
                    print('Invalid Input.')

            if uInput in ['inbox', 'i']:
                inboxMessages = json.loads(self.api.getAllInboxMessages())
                numMessages = len(inboxMessages['inboxMessages'])

                while True:
                    try:
                        msgNum = int(self.userInput('\nWhat is the number of the message you wish to save?').lower())
                        if msgNum >= numMessages:
                            print('Invalid Message Number.')
                        else:
                            break
                    except ValueError:
                        print("That's not a whole number.")

                subject = base64.b64decode(inboxMessages['inboxMessages'][msgNum]['subject'])
                # Don't decode since it is done in the saveFile function
                message = inboxMessages['inboxMessages'][msgNum]['message']

            elif uInput in ['outbox', 'o']:
                outboxMessages = json.loads(self.api.getAllSentMessages())
                numMessages = len(outboxMessages['sentMessages'])

                while True:
                    try:
                        msgNum = int(self.userInput('\nWhat is the number of the message you wish to save?').lower())
                        if msgNum >= numMessages:
                            print('Invalid Message Number.')
                        else:
                            break
                    except ValueError:
                        print("That's not a whole number.")

                subject = base64.b64decode(outboxMessages['sentMessages'][msgNum]['subject'])
                # Don't decode since it is done in the saveFile function
                message = outboxMessages['sentMessages'][msgNum]['message']
            
            subject = '{0}.txt'.format(subject)
            self.saveFile(subject, message)

        # Will delete a message from the system, not reflected on the UI
        elif usrInput in ['delete']:
            uInput = self.userInput('\nWould you like to delete a message from the (I)nbox or (O)utbox?').lower()

            if uInput in ['inbox', 'i']:
                self.deleteInboxMessages()

            elif uInput in ['outbox', 'o']:
                outboxMessages = json.loads(self.api.getAllSentMessages())
                numMessages = len(outboxMessages['sentMessages'])
                
                while True:
                    msgNum = self.userInput('\nEnter the number of the message you wish to delete or (A)ll to empty the outbox.').lower()
                    try:
                        if msgNum in ['all', 'a'] or int(msgNum) == numMessages:
                            break
                        elif int(msgNum) >= numMessages:
                            print('Invalid Message Number')
                        elif int(msgNum) <= numMessages:
                            break
                        else:
                            print('Invalid input')
                    except ValueError:
                        print('Invalid input')

                # Prevent accidental deletion
                uInput = self.userInput('\nAre you sure, (Y)/(n)').lower()

                if uInput in ['yes', 'y']:
                    if msgNum in ['all', 'a'] or int(msgNum) == numMessages:
                        # processes all of the messages in the outbox
                        for msgNum in range (0, numMessages):
                            print('Deleting message {0} of {1}'.format(msgNum+1, numMessages))
                            self.delSentMsg(0)
                        print('Outbox is empty.')
                    else:
                        self.delSentMsg(int(msgNum))
                    print('Notice: Message numbers may have changed.')

        elif usrInput in ['listaddressbookentries']:
            res = self.listAddressBookEntries()
            if res == 20:
                print('Error: API function not supported.')

        elif usrInput in ['addaddressbookentry']:
            while True:
                address = self.userInput('\nEnter address')
                if self.validAddress(address):
                    label = self.userInput('\nEnter label')
                    if label:
                        break
                    else:
                        print('You need to put a label')
                else:
                    print('Invalid address')
            res = self.addAddressToAddressBook(address, label)
            if res == 16:
                print('Error: Address already exists in Address Book.')
            if res == 20:
                print('Error: API function not supported.')

        elif usrInput in ['deleteaddressbookentry']:
            while True:
                address = self.userInput('\nEnter address')
                if self.validAddress(address):
                    res = self.deleteAddressFromAddressBook(address)
                    if res == 20:
                        print('Error: API function not supported.')
                    else:
                        print('{0} has been deleted!'.format(address))
                else:
                    print('Invalid address')

        elif usrInput in ['markallmessagesread']:
            self.markAllMessagesRead()
        elif usrInput in ['markallmessagesunread']:
            self.markAllMessagesUnread()
        else:
            print('"{0}" is not a command.'.format(usrInput))
        self.main()


    def runBM(self):
        try:
            if self.bmActive == False and self.enableBM.poll() is None:
                    os.killpg(os.getpgid(self.enableBM.pid), signal.SIGTERM)
            elif self.bmActive == True and self.enableBM.poll() is None:
                    return
        except AttributeError as e:
            pass

        if sys.platform.startswith('win'):
            self.enableBM = subprocess.Popen([self.programDir + 'bitmessagemain.py'],
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE,
                                              stdin=subprocess.PIPE,
                                              bufsize=0)
        else:
            self.enableBM = subprocess.Popen([self.programDir + 'bitmessagemain.py'],
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE,
                                              stdin=subprocess.PIPE,
                                              bufsize=0,
                                              preexec_fn=os.setpgrp,
                                              close_fds=True)
        my_stdout = self.enableBM.stdout.readlines()
        if 'Another instance' in my_stdout[-1]:
            print('Bitmessage is already running')
            print('Shutting down..')
            sys.exit(0)

        if self.enableBM.poll() is None:
            print('Bitmessage was started')
            self.bmActive = True

    def main(self):
        try:
            self.apiData()
            self.runBM()

            if not self.apiImport:
                self.apiImport = True
                self.api = xmlrpclib.ServerProxy(self.returnApi())

            if not self.apiTest():
                # Bitmessage is running so this may be the first run of apiTest
                if self.bmActive == True and self.enableBM.poll() is None:
                    self.apiImport = True
                else:
                    self.apiImport = False
            else:
                if not self.apiImport:
                    self.apiImport = True

            self.UI(self.userInput('\nType (h)elp for a list of commands.').lower())
        except socket.error:
            self.apiImport = False
            self.UI(self.userInput('\nType (h)elp for a list of commands.').lower())


if __name__ == '__main__':
    my_bitmessage().main()
