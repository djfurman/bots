import bots.communication as communication
import bots.botslib as botslib
import bots.botsglobal as botsglobal
import datetime
import posixpath
import fnmatch
from bots.botsconfig import *
from django.utils.translation import ugettext as _


class sftp(communication.sftp):
    ''' SFTP: SSH File Transfer Protocol (SFTP is not FTP run over SSH, SFTP is not Simple File Transfer Protocol)
        standard port to connect to is port 22.
        requires paramiko and pycrypto to be installed
        based on class ftp and ftps above with code from demo_sftp.py which is included with paramiko
        Mike Griffin 16/10/2010
        Henk-jan ebbers 20110802: when testing I found that the transport also needs to be closed. So changed transport ->self.transport, and close this in disconnect
        henk-jan ebbers 20111019: disabled the host_key part for now (but is very interesting). Is not tested; keys should be integrated in bots also for other protocols.
        henk-jan ebbers 20120522: hostkey and privatekey can now be handled in user exit.
    '''

    def connect(self):
        # check dependencies
        try:
            import paramiko
        except:
            raise ImportError(_('Dependency failure: communicationtype "sftp" requires python library "paramiko".'))
        # setup logging if required
        ftpdebug = botsglobal.ini.getint('settings', 'ftpdebug', 0)
        if ftpdebug > 0:
            log_file = botslib.join(botsglobal.ini.get('directories', 'logging'), 'sftp.log')
            # Convert ftpdebug to paramiko logging level (1=20=info, 2=10=debug)
            paramiko.util.log_to_file(log_file, 30 - (ftpdebug * 10))

        # Get hostname and port to use
        hostname = self.channeldict['host']
        try:
            port = int(self.channeldict['port'])
        except:
            port = 22  # default port for sftp

        if self.userscript and hasattr(self.userscript, 'hostkey'):
            hostkey = botslib.runscript(self.userscript, self.scriptname, 'hostkey', channeldict=self.channeldict)
        else:
            hostkey = None
        if self.userscript and hasattr(self.userscript, 'privatekey'):
            privatekeyfile, pkeytype, pkeypassword = botslib.runscript(
                self.userscript, self.scriptname, 'privatekey', channeldict=self.channeldict)
            if pkeytype == 'RSA':
                if pkeypassword is not None:
                    pkey = paramiko.RSAKey.from_private_key_file(filename=privatekeyfile, password=pkeypassword)
                else:
                    pkey = paramiko.RSAKey.from_private_key_file(filename=privatekeyfile)
            else:
                pkey = paramiko.DSSKey.from_private_key_file(filename=privatekeyfile, password=pkeypassword)
        else:
            pkey = None

        if self.channeldict['secret']:  # if password is empty string: use None. Else error can occur.
            secret = self.channeldict['secret']
        else:
            secret = None
        # now, connect and use paramiko Transport to negotiate SSH2 across the connection
        self.transport = paramiko.Transport((hostname, port))
        self.transport.connect(username=self.channeldict['username'], password=secret, hostkey=hostkey, pkey=pkey)
        self.session = paramiko.SFTPClient.from_transport(self.transport)
        channel = self.session.get_channel()
        channel.settimeout(botsglobal.ini.getint('settings', 'ftptimeout', 10))
        self.set_cwd()

    def set_cwd(self):
        self.session.chdir('.')  # getcwd does not work without this chdir first!
        self.dirpath = self.session.getcwd()
        if self.channeldict['path']:
            self.dirpath = posixpath.normpath(posixpath.join(self.dirpath, self.channeldict['path']))
            try:
                self.session.chdir(self.dirpath)
            except:
                self.session.mkdir(self.dirpath)
                self.session.chdir(self.dirpath)

    def disconnect(self):
        self.session.close()
        self.transport.close()

    @botslib.log_session
    def incommunicate(self):
        ''' do ftp: receive files. To be used via receive-dispatcher.
            each to be imported file is transaction.
            each imported file is transaction.
        '''
        startdatetime = datetime.datetime.now()
        files = self.session.listdir('.')
        lijst = fnmatch.filter(files, self.channeldict['filename'])
        remove_ta = False
        for fromfilename in lijst:  # fetch messages from sftp-server.
            try:
                ta_from = botslib.NewTransaction(filename='sftp:/' + posixpath.join(self.dirpath, fromfilename),
                                                 status=EXTERNIN,
                                                 fromchannel=self.channeldict['idchannel'],
                                                 idroute=self.idroute)
                ta_to = ta_from.copyta(status=FILEIN)
                remove_ta = True
                tofilename = unicode(ta_to.idta)
                # SSH treats all files as binary. paramiko doc says: b-flag is ignored
                fromfile = self.session.open(fromfilename, 'r')
                content = fromfile.read()
                filesize = len(content)
                tofile = botslib.opendata_bin(tofilename, 'wb')
                tofile.write(content)
                tofile.close()
                fromfile.close()
            except:
                txt = botslib.txtexc()
                botslib.ErrorProcess(functionname='sftp-incommunicate', errortext=txt, channeldict=self.channeldict)
                if remove_ta:
                    try:
                        ta_from.delete()
                        ta_to.delete()
                    except:
                        pass
            else:
                ta_to.update(filename=tofilename, statust=OK, filesize=filesize)
                ta_from.update(statust=DONE)
                if self.channeldict['remove']:
                    self.session.remove(fromfilename)
            finally:
                remove_ta = False
                if (datetime.datetime.now() - startdatetime).seconds >= self.maxsecondsperchannel:
                    break

    @botslib.log_session
    def outcommunicate(self):
        ''' do ftp: send files. To be used via receive-dispatcher.
            each to be send file is transaction.
            each send file is transaction.
        '''
        # get right filename_mask & determine if fixed name (append) or files with unique names
        filename_mask = self.channeldict['filename'] if self.channeldict['filename'] else '*'
        if '{overwrite}' in filename_mask:
            filename_mask = filename_mask.replace('{overwrite}', '')
            mode = 'w'
        else:
            mode = 'a'
        for row in botslib.query('''SELECT idta,filename,numberofresends
                                    FROM ta
                                    WHERE idta>%(rootidta)s
                                      AND status=%(status)s
                                      AND statust=%(statust)s
                                      AND tochannel=%(tochannel)s
                                        ''',
                                 {'tochannel': self.channeldict['idchannel'], 'rootidta': self.rootidta,
                                  'status': FILEOUT, 'statust': OK}):
            try:
                ta_from = botslib.OldTransaction(row[str('idta')])
                ta_to = ta_from.copyta(status=EXTERNOUT)
                tofilename = self.filename_formatter(filename_mask, ta_from)
                fromfile = botslib.opendata_bin(row[str('filename')], 'rb')
                # SSH treats all files as binary. paramiko doc says: b-flag is ignored
                tofile = self.session.open(tofilename, mode)
                tofile.write(fromfile.read())
                tofile.close()
                fromfile.close()
                # Rename filename after writing file.
                # Function: safe file writing: do not want another process to read the file while it is being written.
                if self.channeldict['mdnchannel']:
                    tofilename_old = tofilename
                    tofilename = botslib.rreplace(tofilename_old, self.channeldict['mdnchannel'])
                    self.session.rename(tofilename_old, tofilename)
            except:
                txt = botslib.txtexc()
                ta_to.update(statust=ERROR, errortext=txt, filename='sftp:/' + posixpath.join(self.dirpath,
                                                                                              tofilename),
                             numberofresends=row[str('numberofresends')] + 1)
            else:
                ta_to.update(statust=DONE, filename='sftp:/' + posixpath.join(self.dirpath,
                                                                              tofilename),
                             numberofresends=row[str('numberofresends')] + 1)
            finally:
                ta_from.update(statust=DONE)
