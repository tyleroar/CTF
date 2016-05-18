import StringIO
import socket
import re
def trim (str):
   # str = str.replace(' ', '')
   # str = str.replace('\s', '')
    #str = str.replace('\t', '')
    str = str.replace('\r', ' ')
    str = str.replace('\n', ' ')
    return str
def checkfordata(mysocket):
    try:
        tempdata = mysocket.recv(16384)
    except:
        '''no data yet..'''
        return ""
    return tempdata

def checkForDevice(commandReceived, devicelist, socketlist, ship):
    allCommands = commandReceived.split()
    for device in devicelist:
        for tempcommand in allCommands:
            if (device.find(str(tempcommand)) > -1 and tempcommand.find("device") < 0 and len(tempcommand) > 3 and tempcommand.find("system")<0 and tempcommand.find("drive")<0 and tempcommand.find("STAGE")<0 and tempcommand.find("ship")<0 and tempcommand.find("rockets")<0 and tempcommand.find("instant")<0):
                i = devicelist.index(device)
                print "found a command(" + str(tempcommand) + ") i have a device for"
                print "full command:" + commandReceived
                end=len(commandReceived)
                if (commandReceived.find("BRRRR") == 0):
                    end = commandReceived.find("BRRR")
                    commandReceived = commandReceived[45:]
                elif (commandReceived.find("BRRRR")>-1):
                    end=commandReceived.find("BRRR")
                    commandReceived=commandReceived[:end]

                if (commandReceived.find("FWOOSH") > -1):
                    beg = commandReceived.find("FWOOSH")
                    beg=beg+42 # end of the FWOOSH shit
                    commandReceived = commandReceived[beg:]
                print (str(i) + "sending command: " + str(commandReceived) + "\n")
                player=socketlist[i]
                player.send(str(commandReceived) + "\n")
                return
    print str(ship) + "Unable to find someone to execute:" + commandReceived
address="104.196.3.198"
port=45429

sock = socket.socket()
sock.connect((address, port))
data=sock.recv(16384)
#print "Recved: " + data
data=sock.recv(16384)
#print "Recved: " + data
#pos=data.find("Player 0, connect to port")
#print "pos is " + str(pos)
s = StringIO.StringIO(data)
ports=list()
for line in s:
    #print "line is:" + str(line)
    port=line[26:]
    port=port.strip()
    print "port is:" + port
    ports.append(port)
temp = list()
n = 0
sockets = []
player0=socket.socket()
player0.connect((address,int(ports[0])))
player1=socket.socket()
player1.connect((address,int(ports[1])))
player2=socket.socket()
player2.connect((address,int(ports[2])))
player3=socket.socket()
player3.connect((address,int(ports[3])))
player4=socket.socket()
player4.connect((address,int(ports[4])))
player5=socket.socket()
player5.connect((address,int(ports[5])))
player6=socket.socket()
player6.connect((address,int(ports[6])))
player7=socket.socket()
player7.connect((address,int(ports[7])))
player0.setblocking(0)
player1.setblocking(0)
player2.setblocking(0)
player3.setblocking(0)
player4.setblocking(0)
player5.setblocking(0)
player6.setblocking(0)
player7.setblocking(0)
sock.setblocking(0)
socketlist = list()
devicelist = list()
#socketlist.append(socket)
socketlist.append( player0)
socketlist.append(player1)
socketlist.append(player2)
socketlist.append(player3)
socketlist.append(player4)
socketlist.append(player5)
socketlist.append(player6)
socketlist.append(player7)

devicelist=["","","","","","","","",""]
tempdata=""
m=""
devices=0
pos=tempdata.find("Your devices")
while (devices<8):
    for player in socketlist:
        i = socketlist.index(player)
        tempdata = checkfordata(player)
        #tempdata=trim(tempdata)
        if tempdata != "":
            #tempdata = tempdata.strip()
            print str(i) + "received:" + str(tempdata)
            if tempdata.find("devices")>0:
                print "\ndevice: " + str(i) + "found a device: " + str(tempdata) + "\n"
                devices=devices+1
                tempdata=trim(tempdata)
                tempdata=tempdata.strip()
                pos=tempdata.find("devices")
                i = socketlist.index(player)
                end = len(tempdata)-12  #get rid of shit at the end (-----3..)
                devicelist[i] = tempdata[pos+8:end]
                #devicelist.append(tempdata[pos+8:])                print "added: " + tempdata[pos+8:end] + "\n"
            # player.send(str(tempdata) + "\n")
       # tempdata = checkfordata(socket)
        #if tempdata != "":
         #   tempdata = tempdata.strip()
          #  print "Control channel rcvd" + tempdata
for n in range(0,8):
    print "player " + str(n) + " has:" + devicelist[n]
n=0
while 1:
    for player in socketlist:
        tempdata = checkfordata(player)
        i = socketlist.index(player)
        haveDevice = 0
        if tempdata != "":
            tempdata=trim(tempdata)
            if ( (tempdata.find("COMPLETE")>-1) or tempdata.find("STAGE")>-1):
                print (str(i)+"is done with a stage")
                #print str(tempdata)
                #done with this stage...need to update the devicelist
                if tempdata.find("devices") > 0:
                    tempdata = trim(tempdata)
                    print "\ndevice: " + str(i) + "found a device: " + str(tempdata) + "\n"
                    pos = tempdata.find("Your devices")
                    tempdata=tempdata[pos+14:]
                    end=len(tempdata)-12
                    tempdata=tempdata[0:end]
                    print "adding:" + str(tempdata) + "\n"

                    devices = devices + 1
                   # pos = tempdata.find("devices")
                    i = socketlist.index(player)
                    #end = len(tempdata) - 12  # get rid of shit at the end (-----3..)
                    #devicelist[i] = tempdata[pos + 8:end]
                    devicelist[i] = tempdata
                    # devicelist.append(tempdata[pos+8:])
                    print "added:" + tempdata + "\n"
                    for n in range(0, 8):
                        print "player " + str(n) + " has:" + devicelist[n]
            else:
                commandReceived=tempdata


               # print str(i) + "received:" + str(commandReceived)
                i = socketlist.index(player)
                tempdevices = devicelist[i]
              #  print "devices is " + tempdevices
                checkForDevice(commandReceived, devicelist, socketlist, i)

           # print ("found i" + tempstring)
           # player.send(str(tempdata) + "\n")


        tempdata = checkfordata(sock)
        if tempdata != "":
           # tempdata = tempdata.strip()
            print "received on command channel:" + str(tempdata)
print "found Your Devices!"
sock.close()