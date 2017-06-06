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
import socket
import sys
import time
import xmlrpclib
from os import path, environ

APPNAME = 'PyBitmessage'
NULL = ''

class my_bitmessage(object):
    def __init__(self):
        '''
        True = Prompt
        False = Don't Prompt
        '''
        self.usrPrompt = True
        self.api = ''
        self.keysName = 'keys.dat'
        self.keysPath = 'keys.dat'
        self.knownAddresses = {}


    # Checks input for exit or quit. Also formats for input, etc
    def userInput(self, message):
        print('{0}'.format(message))
        try:
            uInput = raw_input('> ').lower().strip()
            if uInput in ['exit', 'x']:
                self.main()
            elif uInput in ['quit', 'q']:
                print('Bye\n')
                sys.exit(0)
            else:
                return uInput
        except (EOFError, KeyboardInterrupt):
            print('')
            sys.exit()


    def userInputStrip(self, message):
        print('{0}'.format(message))
        try:
            uInput = raw_input('> ').strip()
            if uInput.lower() in ['exit', 'x']:
                self.main()
            elif uInput.lower() in ['quit', 'q']:
                print('Bye\n')
                sys.exit(0)
            else:
                return uInput
        except (EOFError, KeyboardInterrupt):
            print('')
            sys.exit()


    # Prompts the user to restart Bitmessage.
    def restartBmNotify(self):
        print('-------------------------------------------------------------------')
        print('WARNING: If Bitmessage is running locally, you must restart it now.')
        print('-------------------------------------------------------------------')


    def safeConfigGetBoolean(self, section, field):
        config = ConfigParser.SafeConfigParser()
        config.read(self.keysPath)
        try:
            return config.getboolean(section,field)
        except Exception as e:
            print(e)
            return False


    '''
    Begin keys.dat interactions
    gets the appropriate folders for the .dat files depending on the OS.
    Taken from bitmessagemain.py
    '''
    def lookupAppdataFolder(self):
        if sys.platform.startswith('darwin'):
            if 'HOME' in environ:
                dataFolder = path.join(os.environ['HOME'],
                                       'Library/Application support/',
                                       APPNAME) + '/'
            else:
                print('Could not find your home folder.')
                print('Please report this message and your OS X version at:')
                print('https://github.com/RZZT/taskhive-core')
                sys.exit()
        elif sys.platform.startswith('win'):
            dataFolder = path.join(environ['APPDATA'],
                                   APPNAME) + '\\'
        else:
            dataFolder = path.expanduser(path.join('~',
                                        '.config/' + APPNAME + '/'))
        return dataFolder


    def configInit(self):
        config = ConfigParser.SafeConfigParser()
        config.add_section('bitmessagesettings')

        '''
        Sets the bitmessage port to stop the warning about
        the api not properly being setup.
        This is in the event that the keys.dat is in a different directory
        or is created locally to connect to a machine remotely.
        '''
        config.set('bitmessagesettings', 'port', '8444')

        # Sets apienabled to true in keys.dat
        config.set('bitmessagesettings','apienabled','true')

        with open(self.keysName, 'wb') as configfile:
            config.write(configfile)

        print('{0} Initalized in the same directory as daemon.py'.format(str(self.keysName)))
        print('You will now need to configure the {0} file.'.format(str(self.keysName)))


    def apiInit(self, apiEnabled):
        config = ConfigParser.SafeConfigParser()
        config.read(self.keysPath)

        # API information there but the api is disabled
        if apiEnabled is False:
            print('The API is not enabled.')
            uInput = self.userInput('Would you like to enable it now? Y/n: ')

            # Sets apienabled to true in keys.dat
            if uInput in ['y', 'yes']:
                config.set('bitmessagesettings','apienabled','true')
                with open(self.keysPath, 'wb') as configfile:
                    config.write(configfile)
                print('API now Enabled')
                self.restartBmNotify()
                return True

            elif uInput in ['no', 'n']:
                print('\n------------------------------------------------------------')
                print('        Daemon will not work when the API is disabled.')
                print('Please refer to the Bitmessage Wiki on how to setup the API.')
                print('------------------------------------------------------------')
            else:
                print('Invalid Entry')
            self.main()

        # API correctly setup
        elif apiEnabled is True:
            # Everything is as it should be
            return True
 
        # API information was not present.
        else:
            print('{0} is not properly configured!'.format(str(self.keysPath)))
            uInput = self.userInput('Would you like to do this now, (Y)/(n)')

            # User said yes so initalize the api by
            # writing these values to the keys.dat file
            if uInput in ['yes', 'y']:
                apiUsr = self.userInput('API Username')
                apiPwd = self.userInput('API Password')
                apiInterface = self.userInput('API Interface (127.0.0.1)')
                apiPort = self.userInput('API Port (8444)')
                apiEnabled = self.userInput('API Enabled? (True) / (False)')
                daemon = self.userInput('Daemon mode Enabled? (True) / (False)')

                if daemon not in ['true', 'false']:
                    print('Invalid Entry for Daemon')

                '''
                sets the bitmessage port to stop the warning about the api
                not properly being setup.
                This is in the event that the keys.dat is in a different
                directory or is created locally to connect to a machine
                remotely.
                '''
                config.set('bitmessagesettings', 'port', '8444')
                config.set('bitmessagesettings', 'apienabled', 'true')
                config.set('bitmessagesettings', 'apiport', apiPort)
                config.set('bitmessagesettings', 'apiinterface', '127.0.0.1')
                config.set('bitmessagesettings', 'apiusername', apiUsr)
                config.set('bitmessagesettings', 'apipassword', apiPwd)
                config.set('bitmessagesettings', 'daemon', daemon)
                with open(self.keysPath, 'wb') as configfile:
                    config.write(configfile)
                print('Finished configuring the keys.dat file with API information.\n')
                self.restartBmNotify()

            elif uInput in ['no', 'n']:
                print('------------------------------------------------------------')
                print('Please refer to the Bitmessage Wiki on how to setup the API.')
                print('------------------------------------------------------------\n')
            else:
                print('Invalid entry')
            self.main()


    def apiData(self):
        config = ConfigParser.SafeConfigParser()

        # First try to load the config file (the keys.dat file)
        # from the program directory    
        config.read(self.keysPath)

        try:
            config.get('bitmessagesettings','port')
            appDataFolder = ''
        except Exception as e:
            # Could not load the keys.dat file in the program directory.
            # Perhaps it is in the appdata directory.
            appDataFolder = self.lookupAppdataFolder()
            self.keysPath = appDataFolder + self.keysPath
            config = ConfigParser.SafeConfigParser()
            config.read(self.keysPath)

            try:
                config.get('bitmessagesettings','port')
            except Exception as e:
                # keys.dat was not there either, something is wrong.
                print('\n------------------------------------------------------------------')
                print('There was a problem trying to access the Bitmessage keys.dat file')
                print('             or keys.dat is not set up correctly')
                print('Make sure that daemon is in the same directory as Bitmessage. ')
                print('-------------------------------------------------------------------')

                uInput = self.userInput('Would you like to create keys.dat in the local directory, (Y)/(n)?')

                if uInput in ['yes', 'y']:
                    self.configInit()
                    self.keysPath = self.keysName
                    self.usrPrompt = False
                    self.main()
                elif uInput in ['no', 'n']:
                    print('Trying Again.\n')
                    self.usrPrompt = False
                    self.main()
                else:
                    print('Invalid Input.\n')
                self.main()

        # checks to make sure that everything is configured correctly.
        # Excluding apiEnabled, it is checked after.
        try:
            config.get('bitmessagesettings', 'apiport')
            config.get('bitmessagesettings', 'apiinterface')
            config.get('bitmessagesettings', 'apiusername')
            config.get('bitmessagesettings', 'apipassword')
        except Exception as e:
            print(e)
            # Initalize the keys.dat file with API information
            self.apiInit('')

        '''
        keys.dat file was found or appropriately configured,
        allow information retrieval
        if False it will prompt the user, if True it will return True
        '''
        apiEnabled = self.apiInit(self.safeConfigGetBoolean('bitmessagesettings', 'apienabled'))

        # read again since changes have been made
        config.read(self.keysPath)
        apiPort = int(config.get('bitmessagesettings', 'apiport'))
        apiInterface = config.get('bitmessagesettings', 'apiinterface')
        apiUsername = config.get('bitmessagesettings', 'apiusername')
        apiPassword = config.get('bitmessagesettings', 'apipassword')

        print('API data successfully imported')

        # Build the api credentials
        return 'http://{0}:{1}@{2}:{3}/'.format(apiUsername, apiPassword, apiInterface, str(apiPort))
#####
# End keys.dat interactions
#####


    # Tests the API connection to bitmessage.
    # Returns true if it is connected.
    def apiTest(self):
        try:
            result = self.api.add(2,3)
        except Exception as e:
            return False
        if result == 5:
            return True
        else:
            return False


    # Allows the viewing and modification of keys.dat settings.
    def bmSettings(self):
        config = ConfigParser.SafeConfigParser()
        # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.read
        # TODO
        # Read the keys.dat
        config.read(self.keysPath)

        try:
            port = config.get('bitmessagesettings', 'port')
        except Exception as e:
            print(e)
            print('File not found.\n')
            self.usrPrompt = False
            self.main()

        startonlogon = self.safeConfigGetBoolean('bitmessagesettings', 'startonlogon')
        minimizetotray = self.safeConfigGetBoolean('bitmessagesettings', 'minimizetotray')
        showtraynotifications = self.safeConfigGetBoolean('bitmessagesettings', 'showtraynotifications')
        startintray = self.safeConfigGetBoolean('bitmessagesettings', 'startintray')
        defaultnoncetrialsperbyte = config.get('bitmessagesettings', 'defaultnoncetrialsperbyte')
        defaultpayloadlengthextrabytes = config.get('bitmessagesettings', 'defaultpayloadlengthextrabytes')
        daemon = self.safeConfigGetBoolean('bitmessagesettings', 'daemon')

        socksproxytype = config.get('bitmessagesettings', 'socksproxytype')
        sockshostname = config.get('bitmessagesettings', 'sockshostname')
        socksport = config.get('bitmessagesettings', 'socksport')
        socksauthentication = self.safeConfigGetBoolean('bitmessagesettings', 'socksauthentication')
        socksusername = config.get('bitmessagesettings', 'socksusername')
        sockspassword = config.get('bitmessagesettings', 'sockspassword')


        print('-----------------------------------')
        print('|   Current Bitmessage Settings   |')
        print('-----------------------------------')
        print('port = {0}'.format(port))
        print('startonlogon = {0}'.format(str(startonlogon)))
        print('minimizetotray = {0}'.format(str(minimizetotray)))
        print('showtraynotifications = {0}'.format(str(showtraynotifications)))
        print('startintray = {0}'.format(str(startintray)))
        print('defaultnoncetrialsperbyte = {0}'.format(defaultnoncetrialsperbyte))
        print('defaultpayloadlengthextrabytes = {0}'.format(defaultpayloadlengthextrabytes))
        print('daemon = {0}'.format(str(daemon)))
        print('-----------------------------------')
        print('|   Current Connection Settings   |')
        print('-----------------------------------')
        print('socksproxytype = {0}'.format(socksproxytype))
        print('sockshostname = {0}'.format(sockshostname))
        print('socksport = {0}'.format(socksport))
        print('socksauthentication = {0}'.format(str(socksauthentication)))
        print('socksusername = {0}'.format(socksusername))
        print('sockspassword = {0}\n'.format(sockspassword))

        uInput = self.userInput('Would you like to modify any of these settings, (Y)/(n)')

        if uInput in ['yes', 'y']:
            # loops if they mistype the setting name, they can exit the loop with 'exit')
            while True:
                invalidInput = False
                uInput = self.userInput('\nWhat setting would you like to modify?')

                if uInput == 'port':
                    print('Current port number: {0}\n'.format(port))
                    uInput = self.userInput('Enter the new port number.')
                    config.set('bitmessagesettings', 'port', str(uInput))

                elif uInput == 'startonlogon':
                    print('Current status: {0}\n'.format(str(startonlogon)))
                    uInput = self.userInput('Enter the new status.')
                    config.set('bitmessagesettings', 'startonlogon', str(uInput))

                elif uInput == 'minimizetotray':
                    print('Current status: {0}\n'.format(str(minimizetotray)))
                    uInput = self.userInput('Enter the new status.')
                    config.set('bitmessagesettings', 'minimizetotray', str(uInput))

                elif uInput == 'showtraynotifications':
                    print('Current status: {0}\n'.format(str(showtraynotifications)))
                    uInput = self.userInput('Enter the new status.')
                    config.set('bitmessagesettings', 'showtraynotifications', str(uInput))

                elif uInput == 'startintray':
                    print('Current status: {0}\n'.format(str(startintray)))
                    uInput = self.userInput('Enter the new status.')
                    config.set('bitmessagesettings', 'startintray', str(uInput))

                elif uInput == 'defaultnoncetrialsperbyte':
                    print('Current default nonce trials per byte: {0}\n'.format(defaultnoncetrialsperbyte))
                    uInput = self.userInput('Enter the new defaultnoncetrialsperbyte.')
                    config.set('bitmessagesettings', 'defaultnoncetrialsperbyte', str(uInput))

                elif uInput == 'defaultpayloadlengthextrabytes':
                    print('Current default payload length extra bytes: {0}\n'.format(defaultpayloadlengthextrabytes))
                    uInput = self.userInput('Enter the new defaultpayloadlengthextrabytes.')
                    config.set('bitmessagesettings', 'defaultpayloadlengthextrabytes', str(uInput))

                elif uInput == 'daemon':
                    print('Current status: {0}\n'.format(str(daemon)))
                    uInput = self.userInput('Enter the new status.')
                    config.set('bitmessagesettings', 'daemon', str(uInput))

                elif uInput == 'socksproxytype':
                    print('Current socks proxy type: {0}'.format(socksproxytype))
                    print("Possibilities: 'none', 'SOCKS4a', 'SOCKS5'\n")
                    uInput = self.userInput('Enter the new socksproxytype')
                    config.set('bitmessagesettings', 'socksproxytype', str(uInput))

                elif uInput == 'sockshostname':
                    print('Current socks host name: {0}\n'.format(sockshostname))
                    uInput = self.userInput('Enter the new sockshostname')
                    config.set('bitmessagesettings', 'sockshostname', str(uInput))

                elif uInput == 'socksport':
                    print('Current socks port number: {0}\n'.format(socksport))
                    uInput = self.userInput('Enter the new socksport')
                    config.set('bitmessagesettings', 'socksport', str(uInput))

                elif uInput == 'socksauthentication':
                    print('Current status: {0}\n'.format(str(socksauthentication)))
                    uInput = self.userInput('Enter the new status')
                    config.set('bitmessagesettings', 'socksauthentication', str(uInput))

                elif uInput == 'socksusername':
                    print('Current socks username: {0}\n'.format(socksusername))
                    uInput = self.userInput('Enter the new socksusername')
                    config.set('bitmessagesettings', 'socksusername', str(uInput))

                elif uInput == 'sockspassword':
                    print('Current socks password: {0}\n'.format(sockspassword))
                    uInput = self.userInput('Enter the new sockspassword')
                    config.set('bitmessagesettings', 'sockspassword', str(uInput))

                else:
                    print('Invalid input. Please try again.\n')
                    invalidInput = True

                # don't prompt if they made a mistake. 
                if not invalidInput:
                    uInput = self.userInput('\nWould you like to change another setting, (Y)/(n)')

                    if uInput not in ['yes', 'y']:
                        with open(self.keysPath, 'wb') as configfile:
                            config.write(configfile)
                        print('Changes made\n')
                        self.restartBmNotify()
                        break
        elif uInput in ['no', 'n']:
            pass
        else:
            print('Invalid input.')
        self.main()


    def validAddress(self, address):
        address_information = json.loads(self.api.decodeAddress(address))
        if 'success' in address_information.get('status'):
            return True
        else:
            return False


    def getAddress(self, passphrase, vNumber, sNumber):
        # passphrase must be encoded
        passphrase = base64.b64encode(passphrase)
        return self.api.getDeterministicAddress(passphrase,vNumber,sNumber)


    def subscribe(self):
        while True:
            address = self.userInputStrip('\nAddress you would like to subscribe to:')
            if self.validAddress(address):
                label = self.userInputStrip('\nEnter a label for this address:')
                label = base64.b64encode(label)
                break
            else:
                print('Not a valid address, please try again.')
        self.api.addSubscription(address, label)
        print('You are now subscribed to: {0}'.format(address))


    def unsubscribe(self):
        while True:
            address = self.userInputStrip('\nEnter the address to unsubscribe from:')
            if self.validAddress(address):
                uInput = self.userInput('\nAre you sure, (Y)/(n)')
                if uInput in ['yes', 'y']:
                    self.api.deleteSubscription(address)
                    print('You are now unsubscribed from: ' + address)
                else:
                    print("You weren't unsubscribed from anything.")
                break


    def listSubscriptions(self):
        try:
            total_subscriptions = json.loads(self.api.listSubscriptions())
            print('-------------------------------------')
            for each in total_subscriptions['subscriptions']:
                print('Label: {0}'.format(base64.b64decode(each['label'])))
                print('Address: {0}'.format(each['address']))
                print('Enabled: {0}'.format(each['enabled']))
                print('-------------------------------------')
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    def createChan(self):
        password = self.userInputStrip('\nEnter channel name:')
        password = base64.b64encode(password)
        try:
            print('Channel password: ' + self.api.createChan(password))
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    def joinChan(self):
        address = self.userInputStrip('\nEnter Channel Address:')
        if self.validAddress(address):
            password = self.userInputStrip('\nEnter Channel Name:')
            password = base64.b64encode(password)
            try:
                joiningChannel = self.api.joinChan(password, address)
                if joiningChannel == 'success':
                    print('Successfully joined {0}'.format(address))
                elif joiningChannel.endswith('list index out of range'):
                    print("You're already in that channel")
            except Exception as e:
                print('Connection Error\n')
                self.usrPrompt = False
                self.main()


    def leaveChan(self):
        while True:
            address = self.userInputStrip('\nEnter Channel Address or Label:')
            if self.validAddress(address):
                break
            else:
                jsonAddresses = json.loads(self.api.listAddresses())
                # Number of addresses
                numAddresses = len(jsonAddresses['addresses'])
                # processes all of the addresses and lists them out
                for addNum in range (0, numAddresses):
                    label = str(jsonAddresses['addresses'][addNum]['label'])
                    jsonAddress = str(jsonAddresses['addresses'][addNum]['address'])
                    if '[chan] {0}'.format(address) == label:
                        address = jsonAddress
                        found = True
                        break
            if found:
                break
        try:
            leavingChannel = self.api.leaveChan(address)
            if leavingChannel == 'success':
                print('Successfully left {0}'.format(address))
            else:
                print(leavingChannel)
        except Exception as e:
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    # Lists all of the addresses and their info
    def listAdd(self):
        try:
            jsonAddresses = json.loads(self.api.listAddresses())
            # Number of addresses
            numAddresses = len(jsonAddresses['addresses'])
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()

        print('-------------------------------------')
        for each in jsonAddresses['addresses']:
            print('Label: {0}'.format(each['label']))
            print('Address: {0}'.format(each['address']))
            print('Stream: {0}'.format(each['stream']))
            print('Enabled: {0}'.format(each['enabled']))
            print('-------------------------------------')


    # Generate address
    def genAdd(self, lbl, deterministic, passphrase, numOfAdd, addVNum, streamNum, ripe):
        # Generates a new address with the user defined label. non-deterministic
        try:
            if deterministic is False:
                addressLabel = base64.b64encode(lbl)
                generatedAddress = self.api.createRandomAddress(addressLabel)
                return generatedAddress
            # Generates a new deterministic address with the user inputs
            elif deterministic is True:
                passphrase = base64.b64encode(passphrase)
                generatedAddress = self.api.createDeterministicAddresses(passphrase, numOfAdd, addVNum, streamNum, ripe)
                return generatedAddress
            else:
                return 'Entry Error'
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    # Allows attachments and messages/broadcats to be saved
    def saveFile(self, fileName, fileData):
        # This section finds all invalid characters and replaces them with ~
        fileName = fileName.strip()
        fileName = fileName.replace('/', '~')
        #fileName = fileName.replace('\\', '~') How do I get this to work...?
        fileName = fileName.replace(':', '~')
        fileName = fileName.replace('*', '~')
        fileName = fileName.replace('?', '~')
        fileName = fileName.replace("'", '~')
        fileName = fileName.replace('<', '~')
        fileName = fileName.replace('>', '~')
        fileName = fileName.replace('|', '~')

        directory = 'attachments'

        if not os.path.exists(directory):
            os.makedirs(directory)

        filePath = directory + '/' + fileName

        # Begin saving to file
        with open(filePath, 'wb+') as f:
            f.write(base64.b64decode(fileData))

        print('Successfully saved {0}\n'.format(filePath))


    # Allows users to attach a file to their message or broadcast
    def attachment(self):
        theAttachmentS = ''

        while True:
            isImage = False
            theAttachment = ''

            filePath = self.userInputStrip('\nPlease enter the path to the attachment')
            print('\n')

            try:
                with open(filePath):
                    break
            except IOError:
                print('{0} was not found on your filesystem or can not be opened.\n'.format(filePath))
                pass

        while True:
            invSize = os.path.getsize(filePath)
            # Converts to kilobytes
            invSize = (invSize / 1024)
            # Rounds to two decimal places
            round(invSize, 2)

            # If over 200KB
            if invSize > 200.0:
                print('WARNING: The maximum message size including attachments, body, and headers is 262,144 bytes.')
                print("If you reach over this limit, your message won't send.")
                uInput = self.userInput('Are you sure you still want to attach it, (Y)/(n)')

                if uInput not in ['yes', 'y']:
                    print('Attachment discarded.\n')
                    return ''

            # If larger than 262KB, discard
            elif invSize > 262.0:
                print('Attachment too big, maximum allowed size is 262KB\n')
                self.main()

            # Gets the length of the filepath excluding the filename
            pathLen = len(str(ntpath.basename(filePath)))
            # reads the filename
            fileName = filePath[(len(str(filePath)) - pathLen):]

            # Tests if it is an image file
            filetype = imghdr.what(filePath)
            if filetype is not None:
                print('---------------------------------------------------')
                print('Attachment detected as an Image.')
                print('<img> tags will automatically be included,')
                print('allowing the recipient to view the image')
                print('using the ''View HTML code...'' option in Bitmessage.')
                print('---------------------------------------------------\n')
                isImage = True
                time.sleep(2)

            # Alert the user that the encoding process may take some time
            print('Encoding attachment, please wait ...\n')

            # Begin the actual encoding
            with open(filePath, 'rb') as f:
                # Reads files up to 262KB
                data = f.read(262000)
                data = base64.b64encode(data)

            # If it is an image, include image tags in the message
            if isImage is True:
                theAttachment = """
<!-- Note: Image attachment below. Please use the right click "View HTML code ..." option to view it. -->
<!-- Sent using Bitmessage Daemon. https://github.com/RZZT/taskhive-core -->

Filename:{0}
Filesize:{1}KB
Encoding:base64

<center>
    <div id="image">
        <img alt = "{2}" src='data:image/{3};base64, {4}' />
    </div>
</center>""".format(fileName, invSize, fileName, filetype, data)
            # Else it is not an image so do not include the embedded image code.
            else:
                theAttachment = """
<!-- Note: File attachment below. Please use a base64 decoder, or Daemon, to save it. -->
<!-- Sent using Bitmessage Daemon. https://github.com/RZZT/taskhive-core -->

Filename:{0}
Filesize:{1}KB
Encoding:base64

<attachment alt = "{2}" src='data:file/{3};base64, {4}' />""".format(fileName, invSize, fileName, fileName, data)

            break

        theAttachmentS = theAttachmentS + theAttachment
        return theAttachmentS


    # With no arguments sent, sendMsg fills in the blanks
    # subject and message must be encoded before they are passed
    def sendMsg(self, toAddress, fromAddress, subject, message):
        if self.validAddress(toAddress) is False:
            while not self.validAddress(toAddress):
                toAddress = self.userInputStrip('\nWhat is the To Address?')
                if self.validAddress(toAddress):
                    break

        if self.validAddress(fromAddress) is False:
            try:
                jsonAddresses = json.loads(self.api.listAddresses().encode('UTF-8'))
                # Number of addresses
                numAddresses = len(jsonAddresses['addresses'])
            except Exception as e:
                print(e)
                print('Connection Error\n')
                self.usrPrompt = False
                self.main()

            # Ask what address to send from if multiple addresses
            if numAddresses > 1:
                found = False
                while True:
                    fromAddress = self.userInputStrip('\nEnter an Address or Address Label to send from')

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
                            print('Invalid Address. Please try again.\n')

                    else:
                        for addNum in range (0, numAddresses):
                            address = jsonAddresses['addresses'][addNum]['address']
                            # address entered was found in our address book
                            if fromAddress == address:
                                found = True
                                break
                        if not found:
                            print('The address entered is not one of yours. Please try again.\n')
                    if found:
                        break

            # Only one address in address book
            else:
                print('Using the only address in the addressbook to send from.')
                fromAddress = jsonAddresses['addresses'][0]['address']

        if subject == '':
            subject = self.userInputStrip('\nEnter your subject')
            subject = base64.b64encode(subject)

        if message == '':
            message = self.userInputStrip('\nEnter your message.')

            uInput = self.userInput('\nWould you like to add an attachment, (Y)/(n)')

            if uInput in ['yes', 'y']:
                message = '{0}\n\n{1}'.format(message, self.attachment())
            message = base64.b64encode(message)

        try:
            ackData = self.api.sendMessage(toAddress, fromAddress, subject, message)
            sendMessage = self.api.getStatus(ackData)
            if sendMessage == 'doingmsgpow':
                print('Message Sent!')
            else:
                print('Could not send Message')
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    # sends a broadcast
    def sendBrd(self, fromAddress, subject, message):
        if fromAddress == '':
            try:
                jsonAddresses = json.loads(self.api.listAddresses().encode('UTF-8'))
                # Number of addresses
                numAddresses = len(jsonAddresses['addresses'])
            except Exception as e:
                print(e)
                print('Connection Error\n')
                self.usrPrompt = False
                self.main()

            # Ask what address to send from if multiple addresses
            if numAddresses > 1:
                found = False
                while True:
                    fromAddress = self.userInputStrip('\nEnter an Address or Address Label to send from')

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
                            print('Invalid Address. Please try again.\n')

                    else:
                        for addNum in range (0, numAddresses):
                            address = jsonAddresses['addresses'][addNum]['address']
                            # address entered was found in our address book
                            if fromAddress == address:
                                found = True
                                break
                        if not found:
                            print('The address entered is not one of yours. Please try again.\n')
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
                subject = self.userInput('Enter your Subject.')
                subject = base64.b64encode(subject)
        if message == '':
                message = self.userInput('Enter your Message.')

                uInput = self.userInput('Would you like to add an attachment, (Y)/(n)')
                if uInput in ['yes', 'y']:
                    message = message + '\n\n' + self.attachment()

                message = base64.b64encode(message)

        try:
            ackData = self.api.sendBroadcast(fromAddress, subject, message)
            sendMessage = self.api.getStatus(ackData)
            if sendMessage == 'broadcastqueued':
                print('Broadcast is now in the queue')
            else:
                print('Could not send Broadcast')
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    # Lists the messages by: Message Number, To Address Label,
    # From Address Label, Subject, Received Time
    def inbox(self, unreadOnly):
        try:
            inboxMessages = json.loads(self.api.getAllInboxMessages())
            numMessages = len(inboxMessages['inboxMessages'])
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()

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
                uInput = self.userInput('(Press Enter to continue or type (Exit) to return to the main menu.)')

        print('-----------------------------------')
        print('There are %d unread messages of %d messages in the inbox.' % (messagesUnread, numMessages))
        print('-----------------------------------')


    def outbox(self):
        try:
            outboxMessages = json.loads(self.api.getAllSentMessages())
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
        numMessages = len(outboxMessages)
        # processes all of the messages in the outbox
        msgNum = 1
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
        try:
            outboxMessages = json.loads(self.api.getAllSentMessages())
            numMessages = len(outboxMessages['sentMessages'])
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
    
        if msgNum >= numMessages:
            print('Invalid Message Number.\n')
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

                uInput = self.userInput('Attachment Detected. Would you like to save the attachment, (Y)/(n)')
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
        try:
            inboxMessages = json.loads(self.api.getAllInboxMessages())
            numMessages = len(inboxMessages['inboxMessages'])
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()

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

                uInput = self.userInput('Attachment Detected. Would you like to save the attachment, (Y)/(n)')
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
        try:
            inboxMessages = json.loads(self.api.getAllInboxMessages())
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()

        # Address it was sent To, now the From address
        fromAdd = inboxMessages['inboxMessages'][msgNum]['toAddress']
        # Message that you are replying too.
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
                toAdd = self.userInput('What is the To Address?')

                if toAdd in ['c']:
                    print('')
                    self.main()
                elif self.validAddress(toAdd) is False:
                    print('Invalid Address. ''c'' to cancel. Please try again.\n')
                else:
                    break
        else:
            print('Invalid Selection. Reply or Forward only')
            self.usrPrompt = False
            self.main()

        subject = base64.b64encode(subject)

        newMessage = self.userInput('Enter your Message.')

        uInput = self.userInput('Would you like to add an attachment, (Y)/(n)')
        if uInput in ['yes', 'y']:
            newMessage = newMessage + '\n\n' + self.attachment()

        newMessage = newMessage + '\n\n------------------------------------------------------\n'
        newMessage = newMessage + message
        newMessage = base64.b64encode(newMessage)

        self.sendMsg(toAdd, fromAdd, subject, newMessage)

        self.main()


    def delMsg(self, msgNum):
        # Deletes a specified message from the inbox
        try:
            inboxMessages = json.loads(self.api.getAllInboxMessages())
            # gets the message ID via the message index number
            msgId = inboxMessages['inboxMessages'][int(msgNum)]['msgid']
            msgAck = self.api.trashMessage(msgId)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
        return msgAck


    # Deletes a specified message from the outbox
    def delSentMsg(self, msgNum):
        
        try:
            outboxMessages = json.loads(self.api.getAllSentMessages())
            # gets the message ID via the message index number
            msgId = outboxMessages['sentMessages'][int(msgNum)]['msgid']
            msgAck = self.api.trashSentMessage(msgId)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
        return msgAck


    def listAddressBookEntries(self):
        try:
            response = self.api.listAddressBookEntries()
            if 'API Error' in response:
                return self.getAPIErrorCode(response)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
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
        try:
            response = self.api.addAddressBookEntry(address, base64.b64encode(label))
            if 'API Error' in response:
                return self.getAPIErrorCode(response)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    def deleteAddressFromAddressBook(self, address):
        try:
            response = self.api.deleteAddressBookEntry(address)
            if 'API Error' in response:
                return self.getAPIErrorCode(response)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    def getAPIErrorCode(self, response):
        if 'API Error' in response:
            # if we got an API error return the number by getting the number
            # after the second space and removing the trailing colon
            return int(response.split()[2][:-1])


    def markMessageRead(self, messageID):
        try:
            response = self.api.getInboxMessageByID(messageID, True)
            if 'API Error' in response:
                return self.getAPIErrorCode(response)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    def markMessageUnread(self, messageID):
        try:
            response = self.api.getInboxMessageByID(messageID, False)
            if 'API Error' in response:
                return self.getAPIErrorCode(response)
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()


    def markAllMessagesRead(self):
        try:
            inboxMessages = json.loads(self.api.getAllInboxMessages())['inboxMessages']
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
        for message in inboxMessages:
            if not message['read']:
                markMessageRead(message['msgid'])


    def markAllMessagesUnread(self):
        try:
            inboxMessages = json.loads(self.api.getAllInboxMessages())['inboxMessages']
        except Exception as e:
            print(e)
            print('Connection Error\n')
            self.usrPrompt = False
            self.main()
        for message in inboxMessages:
            if message['read']:
                markMessageUnread(message['msgid'])


    # Main user menu
    def UI(self, usrInput):
        if usrInput in ['help', 'h', '?']:
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
            self.main()

        # tests the API Connection.
        elif usrInput in ['apitest']:
            if self.apiTest() is True:
                print('API connection test has: PASSED')
            else:
                print('API connection test has: FAILED')
            self.main()

        elif usrInput in ['addinfo']:
            while True:
                address = self.userInputStrip('\nEnter the Bitmessage Address:')
                try:
                    address_information = json.loads(str(self.api.decodeAddress(address)))
                except AttributeError:
                    print('Invalid address!')

                if 'success' in address_information['status']:
                    print('Address Version: {0}'.format(address_information['addressVersion']))
                    print('Stream Number: {0}'.format(address_information['streamNumber']))
                    self.main()
                else:
                    print('Invalid address!')

        # tests the API Connection.
        elif usrInput in ['bmsettings']:
            self.bmSettings()
            self.main()

        # Lists all of the identities in the addressbook
        elif usrInput in ['listaddresses']:
            self.listAdd()
            self.main()

        # Generates a new address
        elif usrInput in ['generateaddress']:
            uInput = self.userInput('\nWould you like to create a (D)eterministic or (R)andom address?')

            # Creates a deterministic address
            if uInput in ['deterministic', 'd']:
                deterministic = True

                lbl = self.userInput('\nLabel the new address:')
                passphrase = self.userInput('\nEnter the Passphrase.')

                try:
                    numOfAdd = int(self.userInput('\nHow many addresses would you like to generate?'))
                except ValueError:
                    print("That's not a whole number.")
                if numOfAdd <= 0:
                    print('How were you expecting that to work?')
                    self.main()
                addVNum = 3
                streamNum = 1
                isRipe = self.userInput('\nShorten the address, (Y)/(n)')
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

                print('Generated Address: {0}'.format(self.genAdd(lbl, deterministic, NULL, NULL, NULL, NULL, NULL)))

            else:
                print('Invalid input\n')
            self.main()

        # Gets the address for/from a passphrase
        elif usrInput in ['getaddress']:
            phrase = self.userInput('\nEnter the address passphrase.')
            print('Working...')
            address = self.getAddress(phrase,4,1)
            print('Address: {0}'.format(address))
            self.main()

        # Subsribe to an address
        elif usrInput in ['subscribe']:
            self.subscribe()
            self.main()

        # Unsubscribe from an address
        elif usrInput in ['unsubscribe']:
            self.unsubscribe()
            self.main()

        # Unsubscribe from an address
        elif usrInput in ['listsubscriptions']:
            self.listSubscriptions()
            self.main()

        elif usrInput in ['create']:
            self.createChan()
            self.main()

        elif usrInput in ['join']:
            self.joinChan()
            self.main()

        elif usrInput in ['leave']:
            self.leaveChan()
            self.main()

        elif usrInput in ['inbox']:
            print('Loading...')
            self.inbox(False)
            self.main()

        elif usrInput in ['unread']:
            print('Loading...')
            self.inbox(True)
            self.main()

        elif usrInput in ['outbox']:
            print('Loading...')
            self.outbox()
            self.main()

        # Sends a message or broadcast
        elif usrInput in ['send']:
            uInput = self.userInput('\nWould you like to send a (M)essage or (B)roadcast?')

            if uInput in ['message', 'm']:
                self.sendMsg(NULL,NULL,NULL,NULL)
                self.main()

            elif uInput in ['broadcast', 'b']:
                self.sendBrd(NULL,NULL,NULL)
                self.main()

        # Opens a message from the inbox for viewing.
        elif usrInput in ['read']:
            uInput = self.userInput('\nWould you like to read a message from the (I)nbox or (O)utbox?')

            if uInput in ['inbox', 'outbox', 'i', 'o']:
                try:
                    msgNum = self.userInput('\nWhat is the number of the message you wish to open?')
                    msgNum = int(msgNum)
                except ValueError:
                    print("That's not a whole number")

                if uInput in ['inbox', 'i']:
                    print('Loading...')
                    messageID = self.readMsg(msgNum)

                    uInput = self.userInput('\nWould you like to keep this message unread, (Y)/(n)')

                    if uInput not in ['yes', 'y']:
                        self.markMessageRead(messageID)

                    uInput = self.userInput('\nWould you like to (D)elete, (F)orward, (R)eply, or E(x)it this message?')

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
                        uInput = self.userInput('\nAre you sure, (Y)/(n)')

                        if uInput in ['yes', 'y']:
                            self.delMsg(msgNum)
                            print('Message Deleted.')
                    else:
                        print('Invalid entry')

                elif uInput in ['outbox', 'o']:
                    self.readSentMsg(msgNum)
                    # Gives the user the option to delete the message
                    uInput = self.userInput('\nWould you like to (D)elete, or (Exit) this message?')

                    if uInput in ['delete', 'd']:
                        # Prevent accidental deletion
                        uInput = self.userInput('Are you sure, (Y)/(n)') 

                        if uInput in ['yes', 'y']:
                            self.delSentMsg(msgNum)
                            print('Message Deleted.')
                    else:
                        print('Invalid Entry')
                    self.usrPrompt
                else:
                    print('Invalid Input.')
                self.main()
            else:
                print('Inbox or Outbox are the only possible answers.')

        elif usrInput in ['save']:
            uInput = self.userInput('Would you like to save a message from the (I)nbox or (O)utbox?')

            if uInput not in ['inbox', 'outbox', 'i', 'o']:
                print('Invalid Input.')
                self.main()

            if uInput in ['inbox', 'i']:
                inboxMessages = json.loads(self.api.getAllInboxMessages())
                numMessages = len(inboxMessages['inboxMessages'])

                while True:
                    try:
                        msgNum = int(self.userInput('What is the number of the message you wish to save?'))
                    except ValueError:
                        print("That's not a whole number.")

                    if msgNum >= numMessages:
                        print('Invalid Message Number.\n')
                    else:
                        break

                subject = base64.b64decode(inboxMessages['inboxMessages'][msgNum]['subject'])
                # Don't decode since it is done in the saveFile function
                message = inboxMessages['inboxMessages'][msgNum]['message']

            elif uInput in ['outbox', 'o']:
                outboxMessages = json.loads(self.api.getAllSentMessages())
                numMessages = len(outboxMessages['sentMessages'])

                while True:
                    try:
                        msgNum = int(self.userInput('What is the number of the message you wish to save?'))
                    except ValueError:
                        print("That's not a whole number.")

                    if msgNum >= numMessages:
                        print('Invalid Message Number.\n')
                    else:
                        break

                subject = base64.b64decode(outboxMessages['sentMessages'][msgNum]['subject'])
                # Don't decode since it is done in the saveFile function
                message = outboxMessages['sentMessages'][msgNum]['message']
            
            subject = '{0}.txt'.format(subject)
            self.saveFile(subject, message)
            self.main()

        # Will delete a message from the system, not reflected on the UI    
        elif usrInput in ['delete']:
            uInput = self.userInput('Would you like to delete a message from the (I)nbox or (O)utbox?')

            if uInput in ['inbox', 'i']:
                inboxMessages = json.loads(self.api.getAllInboxMessages())
                numMessages = len(inboxMessages['inboxMessages'])

                while True:
                    msgNum = self.userInput('Enter the number of the message you wish to delete or (A)ll to empty the inbox.')

                    if msgNum in ['all', 'a']:
                        break
                    elif int(msgNum) >= numMessages:
                        print('Invalid Message Number.\n')
                    else:
                        break

                # Prevent accidental deletion
                uInput = self.userInput('Are you sure, (Y)/(n)')
    
                if uInput in ['yes', 'y']:
                    if msgNum in ['all', 'a']:
                        print('')
                        # Processes all of the messages in the inbox
                        for msgNum in range (0, numMessages):
                            print('Deleting message {0} of '.format(msgNum + 1, numMessages))
                            self.delMsg(0)
    
                        print('Inbox is empty.')
                    else:
                        self.delMsg(int(msgNum))
                        
                    print('Notice: Message numbers may have changed.\n')
                    self.main()
            elif uInput in ['outbox', 'o']:
                outboxMessages = json.loads(self.api.getAllSentMessages())
                numMessages = len(outboxMessages['sentMessages'])
                
                while True:
                    msgNum = self.userInput('Enter the number of the message you wish to delete or (A)ll to empty the inbox.')

                    try:
                        if int(msgNum) >= numMessages:
                            print('Invalid Message Number.\n')
                        else:
                            break
                    except ValueError:
                        if msgNum in ['all', 'a']:
                            break
                        else:
                            print("Input a whole number, 'a', or 'all'")
                            
                # Prevent accidental deletion
                uInput = self.userInput('Are you sure, (Y)/(n)')

                if uInput in ['yes', 'y']:
                    if msgNum in ['all', 'a']:
                        print('')
                        # processes all of the messages in the outbox
                        for msgNum in range (0, numMessages):
                            print('Deleting message {0} of {1}'.format(msgNum+1, numMessages))
                            self.delSentMsg(0)

                        print('Outbox is empty.')
                    else:
                        self.delSentMsg(int(msgNum))
                    print('Notice: Message numbers may have changed.\n')
                    self.main()
            else:
                print('Invalid Entry')
                userPrompt = 1
                self.main()

        elif usrInput in ['listaddressbookentries']:
            res = self.listAddressBookEntries()
            if res == 20:
                print('Error: API function not supported.\n')
            self.main()

        elif usrInput in ['addaddressbookentry']:
            address = self.userInputStrip('\nEnter address')
            label = self.userInputStrip('\nEnter label')
            res = self.addAddressToAddressBook(address, label)
            if res == 16:
                print('Error: Address already exists in Address Book.')
            if res == 20:
                print('Error: API function not supported.')
            self.main()

        elif usrInput in ['deleteaddressbookentry']:
            while True:
                address = self.userInputStrip('\nEnter address')
                if self.validAddress(address):
                    res = self.deleteAddressFromAddressBook(address)
                    if res == 20:
                        print('Error: API function not supported.\n')
                    else:
                        print('{0} has been deleted!'.format(address))
                else:
                    print('Invalid address')
                self.main()

        elif usrInput in ['markallmessagesread']:
            self.markAllMessagesRead()
            self.main()

        elif usrInput in ['markallmessagesunread']:
            self.markAllMessagesUnread()
            self.main()

        else:
            print('"{0}" is not a command.'.format(usrInput))
            self.main()


    def main(self):
        if self.usrPrompt is True:
            print('')
            print(' --------------------------------')
            print('| Bitmessage Daemon by Lvl4Sword |')
            print('|    Version 0.4 for BM 0.6.2    |')
            print(' --------------------------------')
            # Connect to BitMessage using these api credentials
            self.api = xmlrpclib.ServerProxy(self.apiData())

            if self.apiTest() is False:
                print("\n----------------------------------------------------------------")
                print("    WARNING: You are not connected to the Bitmessage client.")
                print("Either Bitmessage is not running or your settings are incorrect.")
                print("Use the command 'apiTest' or 'bmSettings' to resolve this issue.")
                print("----------------------------------------------------------------")
        elif self.usrPrompt is False:
            pass

        self.usrPrompt = False

        try:
            self.UI(self.userInput('\nType (h)elp for a list of commands.'))
        except socket.error:
            print("Could not connect to the API.")
            print("Please check your connection.")
            self.UI(self.userInput('\nType (h)elp for a list of commands.'))


if __name__ == '__main__':
    run = my_bitmessage()
    run.main()
