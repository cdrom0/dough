import ssl
import base64
import dns.message
import dns.resolver
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# chromium-based custom dns config: https://example.net/my-custom-query{?dns}

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

					try:
						dns_request = dns.message.from_wire(dns_query_bytes)

						domain_name = dns_request.question[0].name.to_text()

						resolver = dns.resolver.Resolver()
						resolver.nameservers = ['8.8.8.8']
						
						dns_answer = resolver.resolve(dns_request.question[0].name, dns_request.question[0].rdtype)

						response = dns.message.make_response(dns_request)

						for rdata in dns_answer:
							response.answer.append(dns.rrset.from_rdata(dns_request.question[0].name, 300, rdata))

						response_wire = response.to_wire()

						self.send_response(200)
						self.send_header('Content-Type', 'application/dns-message')
						self.end_headers()
						self.wfile.write(response_wire)
					except:
						pass

				except Exception as e:
					self.send_error(500)
					self.end_headers()
			else:
				self.send_error(400)
				self.end_headers()
		else:
			self.send_error(404)
			self.end_headers()

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
				domain_name = dns_request.question[0].name.to_text()
				print(f"{current_time} - Request from {self.client_address[0]} for {domain_name}")
			except Exception as e:
				print(f"{current_time} - Error extracting domain name: {str(e)}")
		else:
			print(f"{current_time} - Request from {self.client_address[0]} for {self.path}")
			print(f"{current_time} - No DNS query found to decode.")

	def log_message(self, format, *args):
		return


def run_server(server_class=HTTPServer, handler_class=DoHDNSHandler, port=443, cert_file="cert.pem", key_file="key.pem"):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)

	context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	context.load_cert_chain(certfile=cert_file, keyfile=key_file)

	context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable old protocols
	#context.verify_mode = ssl.CERT_NONE  # Do not verify client certificates

	httpd.socket = context.wrap_socket(
		httpd.socket,
		server_side=True
	)

	print(f"Starting DoH server on port {port}...")
	httpd.serve_forever()

if __name__ == '__main__':
	run_server()
