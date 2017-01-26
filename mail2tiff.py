import sys
sys.dont_write_bytecode = True

import os
from shutil import copy
import configparser
from datetime import datetime
import smtpd
import asyncore
import json
import re, email, csv, base64, json
from datetime import datetime
from io import StringIO
from subprocess import Popen, PIPE, STDOUT, DEVNULL
from threading import Timer
from glob import glob

smtpd.__version__ = 'This SMTP daemon developed by GTC. support@georgiatc.com'

config = configparser.ConfigParser()
config.read('config.ini')

try:
	# PyInstaller creates a temp folder and stores path in _MEIPASS
	base_path = sys._MEIPASS
	os.environ["PATH"] += os.pathsep + sys._MEIPASS
except Exception:
	base_path = os.path.abspath(".")

def main():
	server = CustomSMTPServer((config['SERVER']['listen_ip'], int(config['SERVER']['listen_port'])), None)
	print ("SMTP daemon started.")
	print ("listening on", config['SERVER']['listen_ip'] + ":" + config['SERVER']['listen_port'])
	flushOutput()
	asyncore.loop()
	
def flushOutput():	# this thread loops every second and flushes the stderr and stdout
	sys.stdout.flush()
	sys.stderr.flush()
	flushOutput_thread = Timer(1, flushOutput)
	flushOutput_thread.daemon = True
	flushOutput_thread.start()

class CustomSMTPServer(smtpd.SMTPServer):
	def process_message(self, peer, mailfrom, rcpttos, message_data):
		print ()
		print ('process_message triggered. Processing...')
		print ('Receiving message from:', peer)
		print ('Message addressed from:', mailfrom)
		print ('Message addressed to	 :', rcpttos)
		print ('Message length		 :', len(message_data))
		
		if rcpttos[0] not in config['ADDRESS_MAP']:
			print('=== Not To Valid Recpt: Ignoring ====' + '\n')
		else:
			destination = config['ADDRESS_MAP'][rcpttos[0]]
			mj = MailJson(message_data)
			mj.parse()
			mailObject = mj.get_data()
			mailObject['rcpttos'] = rcpttos;
			mailObject['mailfrom'] = mailfrom;
			mailObject['peer'] = peer;
			html_message = None

			for part in mailObject['message']:
				# might need to extract part['headers']['encoding'] or something to pass correct
				# encoding to the HTML file we build. right now it's mailObject['encoding']
				# which is always utf-8.
				if part['content_type'] == 'text/html':
					html_message = part['content'].strip()
				if part['content_type'] == 'text/plain':
					text_message = part['content']
			if html_message == None:
				html_message = '<html><head><meta charset="' + mailObject['encoding'] + '"></head><body><pre>' + text_message + '</pre></body></html>'
				html_message = html_message
			if html_message[:6].lower() != '<html>':
				html_message = '<html><head><meta charset="' + mailObject['encoding'] + '"></head><body>' + html_message + '</body></html>'
				html_message = html_message
			filename = datetime.now().strftime("%Y-%m-%d-%H.%M.%S.") + str(datetime.now().microsecond) + '_'
			filename += mailObject['from'][0]['name'].replace(' ', '_') + '__'
			filename += mailObject['from'][0]['email']
			html_file = open(filename + '.html', 'wb')
			html_file.write(bytes(html_message, 'utf-8'))
			html_file.close()
			command = [base_path + '\wkhtmltopdf.exe', '--margin-bottom', '9', '--margin-left', '9', '--margin-right', '9', '--margin-top', '9', '--image-quality', '99', '--page-size', 'Letter', '--print-media-type', filename + '.html', filename + '.pdf']
			process = Popen(command, stdout=PIPE, stderr=PIPE)
			process.wait()
			if process.returncode == 0:
				os.remove(filename + '.html')
				command = [base_path + '\convert.exe' , '-depth', '8', '-quality', '99', '-density', '200', '-gravity', 'center', '-extent', '1700x2200',	 filename + '.pdf', filename + '.jpg']
				process = Popen(command, stdout=PIPE, stderr=PIPE)
				process.wait()
				if process.returncode == 0:
					os.remove(filename + '.pdf')
					command = [base_path + '\convert.exe', '-compress', 'lzw', filename + '*.jpg', filename + '.tif']
					process = Popen(command, stdout=PIPE, stderr=PIPE)
					process.wait()
					if process.returncode == 0:
						for f in glob(filename + '*.jpg'):
							os.remove(f)
						try:
							copy(filename + '.tif', destination)
						except:
							print ("could not copy " , filename, "to", destination)
						else:
							os.remove(filename + '.tif')
							print('=== Image File Delivered ====' + '\n')
					else:
						print (base_path + "\convert.exe (jpg to tif) exited with" , process.returncode)
				else:
					print (base_path + "\convert.exe (pdf to jpg) exited with" , process.returncode)
			else:
				print (base_path + "\wkhtmltopdf.exe exited with" , process.returncode)


class MailJson:

	# regular expresion from https://github.com/django/django/blob/master/django/core/validators.py
	email_re = re.compile(
		r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"	# dot-atom
		# quoted-string, see also http://tools.ietf.org/html/rfc2822#section-3.2.5
		r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'
		r')@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$)'  # domain
		r'|\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$', re.IGNORECASE)

	email_extract_re = re.compile("<(([.0-9a-z_+-=]+)@(([0-9a-z-]+\.)+[0-9a-z]{2,9}))>", re.M|re.S|re.I)
	filename_re = re.compile("filename=\"(.+)\"|filename=([^;\n\r\"\']+)", re.I|re.S)

	begin_tab_re = re.compile("^\t{1,}", re.M)
	begin_space_re = re.compile("^\s{1,}", re.M)

	def __init__(self, content = None):
		self.data = {}
		self.raw_parts = []
		self.encoding = "utf-8" # output encoding
		self.setContent(content)

	def setEncoding(self, encoding):
		self.encoding = encoding

	def setContent(self, content):
		self.content = content

	def _fixEncodedSubject(self, subject):
		if subject is None:
			return ""

		subject = "%s" % subject
		subject = subject.strip()

		if len(subject) < 2:
			# empty string or not encoded string ?
			return subject
		if subject.find("\n") == -1:
			# is on single line
			return subject
		if subject[0:2] != "=?":
			# not encoded
			return subject

		subject = subject.replace("\r", "")
		subject = self.begin_tab_re.sub("", subject)
		subject = self.begin_space_re.sub("", subject)
		lines = subject.split("\n")

		new_subject = ""
		for l in lines:
			new_subject = "%s%s" % (new_subject, l)
			if l[-1] == "=":
				new_subject = "%s\n " % new_subject

		return new_subject

	def _extract_email(self, s):
		ret = self.email_extract_re.findall(s)
		if len(ret) < 1:
			p = s.split(" ")
			for e in p:
				e = e.strip()
				if self.email_re.match(e):
					return e

			return None
		else:
			return ret[0][0]

	def _decode_headers(self, v):
		if type(v) is not list:
			v = [ v ]

		ret = []
		for h in v:
			h = email.header.decode_header(h)
			h_ret = []
			for h_decoded in h:
				hv = h_decoded[0]
				h_encoding = h_decoded[1]
				if h_encoding is None:
					h_encoding = "ascii"
				else:
					h_encoding = h_encoding.lower()

				hv = str(hv.encode(self.encoding), h_encoding).strip().strip("\t")


				h_ret.append(hv.encode(self.encoding))

			ret.append(str(b" ".join(h_ret), self.encoding))

		return ret

	def _parse_recipients(self, v):
		if v is None:
			return None

		ret = []

		# Sometimes a list is passed, which breaks .replace()
		if isinstance(v, list):
			v = ",".join(v)
		v = v.replace("\n", " ").replace("\r", " ").strip()
		s = StringIO(v)
		c = csv.reader(s)
		try:
			row = next(c)
		except StopIteration:
			return ret

		for entry in row:
			entry = entry.strip()
			if self.email_re.match(entry):
				e = entry
				entry = ""
			else:
				e = self._extract_email(entry)
				entry = entry.replace("<%s>" % e, "")
				entry = entry.strip()
				if e and entry.find(e) != -1:
					entry = entry.replace(e, "").strip()

			# If all else has failed
			if entry and e is None:
				e_split = entry.split(" ")
				e = e_split[-1].replace("<", "").replace(">","")
				entry = " ".join(e_split[:-1])

			ret.append({"name": entry, "email": e})

		return ret

	def _parse_date(self, v):
		if v is None:
			return datetime.now()

		tt = email.utils.parsedate_tz(v)

		if tt is None:
			return datetime.now()

		timestamp = email.utils.mktime_tz(tt)
		date = datetime.fromtimestamp(timestamp)
		return date

	def _get_part_headers(self, part):
		# raw headers
		headers = {}
		for k in list(part.keys()):
			k = k.lower()
			v = part.get_all(k)
			v = self._decode_headers(v)

			if len(v) == 1:
				headers[k] = v[0]
			else:
				headers[k] = v

		return headers

	def parse(self):
		self.msg = email.message_from_bytes(bytes(self.content, 'utf-8'))
		
		content_charset = self.msg.get_content_charset()
		if content_charset == None:
			content_charset = 'utf-8'

		headers = self._get_part_headers(self.msg)
		self.data["headers"] = headers
		self.data["datetime"] = self._parse_date(headers.get("date", None)).strftime("%Y-%m-%d %H:%M:%S")
		self.data["subject"] = self._fixEncodedSubject(headers.get("subject", None))
		self.data["to"] = self._parse_recipients(headers.get("to", None))
		self.data["reply-to"] = self._parse_recipients(headers.get("reply-to", None))
		self.data["from"] = self._parse_recipients(headers.get("from", None))
		self.data["cc"] = self._parse_recipients(headers.get("cc", None))

		attachments = []
		parts = []
		for part in self.msg.walk():
			if part.is_multipart():
				continue

			content_disposition = part.get("Content-Disposition", None)
			if content_disposition:
				# we have attachment
				r = self.filename_re.findall(content_disposition)
				if r:
					filename = sorted(r[0])[1]
				else:
					filename = "undefined"

				a = { "filename": filename, "content": base64.b64encode(part.get_payload(decode = True)), "content_type": part.get_content_type() }
				attachments.append(a)
			else:
				try:
					p = { "content_type": part.get_content_type(), "content": str(part.get_payload(decode = 1), content_charset, "ignore"), "headers": self._get_part_headers(part) }
					parts.append(p)
					self.raw_parts.append(part)
				except LookupError:
					# Sometimes an encoding isn't recognised - not much to be done
					pass

		self.data["attachments"] = attachments
		self.data["message"] = parts
		self.data["encoding"] = self.encoding

		return self.get_data()

	def get_data(self):
		return self.data

	def get_raw_parts(self):
		return self.raw_parts

if __name__ == "__main__":
	main()
