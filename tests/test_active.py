import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.run_active import parse_and_generate_jsonl, parse_gobuster, parse_nmap_xml


NMAP_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" />
        <service name="ftp" product="vsftpd" version="3.0.2" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.31.4" />
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed" />
      </port>
    </ports>
  </host>
</nmaprun>
'''


class TestActiveCollectorParsing(unittest.TestCase):
    def test_parse_nmap_discovers_open_services_and_http_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = os.path.join(directory, 'nmap.xml')
            with open(xml_path, 'w', encoding='utf-8') as output:
                output.write(NMAP_XML)

            records, http_ports = parse_nmap_xml(xml_path)

        self.assertEqual(http_ports, [('127.0.0.1', '80')])
        self.assertEqual([record['id'] for record in records], [
            'host-127.0.0.1', 'svc-127.0.0.1-21', 'svc-127.0.0.1-80'
        ])
        self.assertEqual(records[1]['attrs']['version'], '3.0.2')

    def test_parse_gobuster_normalizes_paths_and_status(self):
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as output:
            output.write('backup (Status: 301) [Size: 169]\n')
            output.write('/.git (Status: 200) [Size: 42]\n')
            output.write('not-a-result\n')
            gobuster_path = output.name
        try:
            records = parse_gobuster(gobuster_path, '127.0.0.1', '80')
        finally:
            os.unlink(gobuster_path)

        self.assertEqual([record['attrs']['path'] for record in records], ['/backup', '/.git'])
        self.assertEqual(records[1]['attrs']['status'], 200)
        self.assertEqual(records[1]['attrs']['severity'], 0.75)

    def test_jsonl_generation_joins_gobuster_results_by_host_and_port(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = os.path.join(directory, 'nmap.xml')
            gobuster_path = os.path.join(directory, 'gobuster_80.txt')
            jsonl_path = os.path.join(directory, 'active.jsonl')
            with open(xml_path, 'w', encoding='utf-8') as output:
                output.write(NMAP_XML)
            with open(gobuster_path, 'w', encoding='utf-8') as output:
                output.write('backup (Status: 301)\n')

            parse_and_generate_jsonl(
                xml_path, {('127.0.0.1', '80'): gobuster_path}, jsonl_path
            )
            with open(jsonl_path, encoding='utf-8') as output:
                records = [json.loads(line) for line in output if line.strip()]

        self.assertEqual(len(records), 4)
        self.assertEqual(records[-1]['id'], 'path-127.0.0.1-80-backup')


if __name__ == '__main__':
    unittest.main()
