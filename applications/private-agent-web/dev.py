#!/usr/bin/env python3
"""Serve the built page and same-origin public broker endpoints for browser checks."""
import argparse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
import mimetypes
ROOT=Path(__file__).resolve().parent/'dist'
class Handler(BaseHTTPRequestHandler):
 def do_GET(self): self.handle_request()
 def do_POST(self): self.handle_request()
 def log_message(self,*args): pass
 def handle_request(self):
  if self.path.startswith('/relay-broker/'):
   size=int(self.headers.get('content-length','0'))
   if size>48*1024*1024+16384:self.send_error(413);return
   req=Request('https://pod.dstack.soc1024.com'+self.path,data=self.rfile.read(size) if size else None,method=self.command,headers={'content-type':'application/json'})
   try: response=urlopen(req,timeout=920)
   except HTTPError as error:response=error
   self.send_response(response.status);self.send_header('Content-Type',response.headers.get('Content-Type','application/json'));self.send_header('Cache-Control','no-store');self.end_headers()
   while chunk:=response.read(65536): self.wfile.write(chunk);self.wfile.flush()
   response.close();return
  path=self.path.split('?',1)[0]
  if not path.startswith('/private-agent/') or self.command!='GET':self.send_error(404);return
  relative=path[len('/private-agent/'):] or 'index.html'
  file=(ROOT/relative).resolve()
  if not file.is_relative_to(ROOT) or not file.is_file():self.send_error(404);return
  data=file.read_bytes();self.send_response(200);self.send_header('Content-Type',mimetypes.guess_type(file)[0] or 'application/octet-stream');self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(data)
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=18731);args=parser.parse_args();ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
