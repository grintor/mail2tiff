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
	asyncore.loop()

class CustomSMTPServer(smtpd.SMTPServer):
	def process_message(self, peer, mailfrom, rcpttos, message_data):
		print('process_message triggered. Processing...')
		print ('Receiving message from:', peer)
		print ('Message addressed from:', mailfrom)
		print ('Message addressed to	 :', rcpttos)
		print ('Message length		 :', len(message_data))
		
		if rcpttos[0] not in config['ADDRESS_MAP']:
			print('=== Not To Valid Recpt: Ignoring ====' + '\n')
		else:
			destination = config['ADDRESS_MAP'][rcpttos[0]]
			#p = Popen([base_path + '\mailtojson.exe', '-p'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
			#mailObject = p.communicate(input=bytes(message_data, 'UTF-8'))[0]
			#mailObject = json.loads(mailObject.decode())
			mj = MailJson(message_data)
			mj.parse()
			mailObject = mj.getData()
			mailObject['rcpttos'] = rcpttos;
			mailObject['mailfrom'] = mailfrom;
			mailObject['peer'] = peer;
			html_message = None

			for part in mailObject['message']:
				if part['content_type'] == 'text/html':
					html_message = part['content'].strip()
				if part['content_type'] == 'text/plain':
					text_message = part['content']
			if html_message == None:
				html_message = '<html><head></head><body><pre>' + str(text_message, mailObject['encoding']) + '</pre></body></html>'
				html_message = bytes(html_message, mailObject['encoding'])
			if html_message[:6].lower() != bytes('<html>', 'ascii'):
				html_message = '<html><head><meta charset="' + mailObject['encoding'] + '"></head><body>' + str(html_message, mailObject['encoding']) + '</body></html>'
				html_message = bytes(html_message, mailObject['encoding'])
			filename = datetime.now().strftime("%Y-%m-%d-%H.%M.%S.") + str(datetime.now().microsecond) + '_'
			filename += mailObject['from'][0]['name'].replace(' ', '_') + '__'
			filename += mailObject['from'][0]['email']
			html_file = open(filename + '.html', 'wb')
			html_file.write(html_message)
			html_file.close()
			command = [base_path + '\wkhtmltopdf.exe', '--margin-bottom', '9', '--margin-left', '9', '--margin-right', '9', '--margin-top', '9', '--image-quality', '99', '--page-size', 'Letter', filename + '.html', filename + '.pdf']
			process = Popen(command, stdout=DEVNULL, stderr=DEVNULL)
			process.wait()
			if process.returncode == 0:
				os.remove(filename + '.html')
				command = [base_path + '\convert.exe' , '-depth', '8', '-compress', 'lzw', '-density', '200', '-gravity', 'center', '-extent', '1700x2200',  filename + '.pdf', filename + '.tif']
				process = Popen(command, shell=True, stdout=PIPE)
				process.wait()
				if process.returncode == 0:
					os.remove(filename + '.pdf')
					try:
						copy(filename + '.tif', destination)
					except:
						pass
					else:
						os.remove(filename + '.tif')
						print('=== Image File Delivered ====' + '\n')
						


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

			ret.append(b" ".join(h_ret).decode("utf-8"))

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

	def _get_content_charset(self, part, failobj = None):
		"""Return the charset parameter of the Content-Type header.

		The returned string is always coerced to lower case.  If there is no
		Content-Type header, or if that header has no charset parameter,
		failobj is returned.
		"""
		missing = object()
		charset = part.get_param("charset", missing)
		if charset is missing:
			return failobj
		if isinstance(charset, tuple):
			# RFC 2231 encoded, so decode it, and it better end up as ascii.
			pcharset = charset[0] or "us-ascii"
			try:
				# LookupError will be raised if the charset isn't known to
				# Python.  UnicodeError will be raised if the encoded text
				# contains a character not in the charset.
				charset = str(charset[2], pcharset).encode("us-ascii")
			except (LookupError, UnicodeError):
				charset = charset[2]
		# charset character must be in us-ascii range
		try:
			if isinstance(charset, str):
				charset = charset.encode("us-ascii")
			charset = str(charset, "us-ascii").encode("us-ascii")
		except UnicodeError:
			return failobj
		# RFC 2046, $4.1.2 says charsets are not case sensitive
		return charset.lower()

	def parse(self):
		self.msg = email.message_from_string(self.content)

		# raw headers
		headers = {}
		for k in list(self.msg.keys()):
			k = k.lower()
			v = self.msg.get_all(k)
			v = self._decode_headers(v)

			if len(v) == 1:
				headers[k] = v[0]
			else:
				headers[k] = v
		self.data["headers"] = headers
		self.data["datetime"] = self._parse_date(headers.get("date", None)).strftime("%Y-%m-%d %H:%M:%S")
		self.data["subject"] = self._fixEncodedSubject(headers.get("subject", None))
		self.data["to"] = self._parse_recipients(headers.get("to", []))
		self.data["reply-to"] = self._parse_recipients(headers.get("reply-to", []))
		self.data["from"] = self._parse_recipients(headers.get("from", []))
		self.data["cc"] = self._parse_recipients(headers.get("cc", []))

		attachments = []
		message = []
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
					p = {"content_type": part.get_content_type(), "content": part.get_payload(decode = True) }
					message.append(p)
				except LookupError:
					# Sometimes an encoding isn't recognised - not much to be done
					pass

		self.data["attachments"] = attachments
		self.data["message"] = message
		self.data["encoding"] = self.encoding
		
		return self.getData()

	def getData(self):
		return self.data

if __name__ == "__main__":
    main()
