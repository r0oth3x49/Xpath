#!/usr/bin/python
#######################################################
#   xpath tool v2.0 - Automated Xpath Sql Injection   #
#       Author: Nasir khan (r0ot h3x49)               #
#######################################################

from os import name as _name
from _compat import (
					compat_connect,
					Drop,
					Create,
					Show,
					Insert,
					Alter,
					Prev,
					Update,
					DumpShow,
					)
class Session:

	def SessionCreate(self, SFile, Table, Cols=None):
		QueryDrop   = Drop % (Table)
		QueryCreate = Create % (Table, Cols)
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryDrop)
				cur.execute(QueryCreate)
			con.commit()
		except Exception as e:
			raise e
		else:
			if con:
				con.close()
	def SessionInsert(self, SFile, Table, Cols=None, Data=None):

		QueryInsert = Insert % (Table, Cols, Data)
		# print QueryInsert
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryInsert)
			con.commit()
		except Exception as e:
			raise e
		else:
			if con:
				con.close()
	def SessionUpdate(self, SFile, Table, Col=None, Data=None):
		QueryUpdate = Update % (Table, Col, Data)
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryUpdate)
			con.commit()
		except Exception as e:
			raise e
		else:
			if con:
				con.close()
	def SessionAlter(self, SFile, Table, Col=None):
		QueryAlter = Alter % (Table, Col)
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryAlter)
			con.commit()
		except Exception as e:
			pass
		else:
			if con:
				con.close()
	def SessionPrev(self, SFile, Table, Col):
		QueryPrev = Prev % (Col, Table)
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryPrev)
				rows = cur.fetchall()
		except Exception as e:
			raise e
		else:
			if con:
				con.close()
			if rows:
				return rows
	def SessionShow(self, SFile, Table):

		QueryShow = Show % (Table)
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryShow)
				rows = cur.fetchall()
		except Exception as e:
			raise e
		else:
			if con:
				con.close()
			if rows:
				return rows
	def SessionDumpShow(self, SFile, Table, Cols=None):
		QueryShow = DumpShow % (Cols, Table)
		con = compat_connect(SFile)
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryShow)
				rows = cur.fetchall()
		except Exception as e:
			raise e
		else:
			if con:
				con.close()
			if rows:
				return rows
	def ShowPrettySession(self, SFile, Table,flag=True,Cols=None):
		con 		= compat_connect(SFile)
		QueryPretty = DumpShow % (Cols, Table) 
		try:
			with con:
				cur = con.cursor()
				cur.execute(QueryPretty)
		except Exception as e:
			raise e
		else:
			if flag:
				return cur
			else:
				if con:
					con.close()
