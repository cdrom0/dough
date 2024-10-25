import ssl
import base64
import dns.message
import dns.resolver
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# chromium-based custom dns config: https://example.net/my-custom-query{?dns}

BLOCKLIST = [] # block domains, list

class DoHDNSHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		if self.path.startswith('/my-custom-query'):
			query = self.path.split('?')[1] if '?' in self.path else ''

			self.log_dns_request(query)

			if 'dns=' in query:
				dns_query_base64 = query.split('dns=')[1]

				try:
					missing_padding = len(dns_query_base64) % 4
					if missing_padding:
						dns_query_base64 += '=' * (4 - missing_padding)

					dns_query_bytes = base64.urlsafe_b64decode(dns_query_base64)

					dns_request = dns.message.from_wire(dns_query_bytes)

					domain_name = dns_request.question[0].name.to_text().rstrip('.')

					if self.is_blocked(domain_name):

						response = dns.message.make_response(dns_request)
						response.set_rcode(dns.rcode.NXDOMAIN)

						response_wire = response.to_wire()
						self.send_response(200)
						self.send_header('Content-Type', 'application/dns-message')
						self.end_headers()
						self.wfile.write(response_wire)

					else:
						resolver = dns.resolver.Resolver()
						dns_answer = resolver.resolve(dns_request.question[0].name, dns_request.question[0].rdtype)

						response = dns.message.make_response(dns_request)

						for rdata in dns_answer:
							response.answer.append(dns.rrset.from_rdata(dns_request.question[0].name, 300, rdata))

						response_wire = response.to_wire()

						self.send_response(200)
						self.send_header('Content-Type', 'application/dns-message')
						self.end_headers()
						self.wfile.write(response_wire)

				except Exception as e:
					self.send_custom_error(500)
			else:
				self.send_custom_error(400)
		else:
			self.send_custom_error(404)

	def is_blocked(self, domain):
		for blocked_domain in BLOCKLIST:
			if domain.endswith(blocked_domain):
				return True
		return False

	def log_dns_request(self, query):
		"""Log DNS request details to the console."""
		current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

		dns_query_base64 = query.split('dns=')[1] if 'dns=' in query else ''

		if dns_query_base64:
			missing_padding = len(dns_query_base64) % 4
			if missing_padding:
				dns_query_base64 += '=' * (4 - missing_padding)
			
			dns_query_decoded = base64.urlsafe_b64decode(dns_query_base64)

			try:
				dns_request = dns.message.from_wire(dns_query_decoded)
				domain_name = dns_request.question[0].name.to_text().rstrip('.')
				if self.is_blocked(domain_name):
					print(f"--> Blocked domain requested: {domain_name} <--")
				else:
					print(f"{current_time} - Request from {self.client_address[0]} for {domain_name}")

			except Exception as e:
				print(f"{current_time} - Error extracting domain name: {str(e)}")
		else:
			#print(f"{current_time} - Request from {self.client_address[0]} for {self.path}")
			print(f"{current_time} - No DNS query found to decode.")

	def log_message(self, format, *args):
		return


	def send_custom_error(self, code):
		self.send_response(code)
		self.send_header('Content-Type', 'text/html')
		self.end_headers()
		
		if code == 404:
			self.wfile.write(b"")
		elif code == 500:
			self.wfile.write(b"")
		elif code == 400:
			self.wfile.write(b"")
		else:
			self.wfile.write(b"")


def run_server(server_class=HTTPServer, handler_class=DoHDNSHandler, port=443, cert_file="cert.pem", key_file="key.pem"):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)

	context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	context.load_cert_chain(certfile=cert_file, keyfile=key_file)

	context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

	httpd.socket = context.wrap_socket(
		httpd.socket,
		server_side=True
	)

	print(f"Starting DoH server on port {port}...")
	httpd.serve_forever()

if __name__ == '__main__':
	run_server()
