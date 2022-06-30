import gzip
import json
import sys
from pathlib import Path

import pandas as pd


def parse_shodan_file(file_path: Path):
    if file_path.suffix == '.gz':
        with gzip.open(str(file_path.absolute()), 'r') as f:
            data = f.read().decode('utf-8').strip()
            data = data.split('\n')
    else:
        with file_path.open() as f:
            data = f.read()

    hosts = []
    for entry in data:
        entry = json.loads(entry)

        host = {
            'ip': entry['ip_str'],
            'port': entry['port'],
            'transport': entry['transport'],
            'product': entry.get('product'),
            'hostnames': ','.join(entry['hostnames']),
            'version': entry.get('version'),
            'data': entry['data'],
            'scan_time': entry['timestamp']
        }

        if 'http' in entry:
            host['web_title'] = entry['http']['title']
            host['web_server'] = entry['http']['server']

        if 'ssl' in entry:
            if 'versions' in entry['ssl']:
                host['ssl_versions'] = ','.join([v for v in entry['ssl']['versions'] if '-' not in v])
            if 'cert' in entry['ssl']:
                host['ssl_issuer'] = entry['ssl']['cert']['issuer']['CN']
                host['ssl_expired'] = entry['ssl']['cert']['expired']
                host['ssl_subject'] = entry['ssl']['cert']['subject']['CN']

        if 'vulns' in entry:
            vulns = entry['vulns']
            host['vulns'] = ','.join(vulns.keys())
            host['vulns_verified'] = any(v['verified'] for v in vulns.values())

        host['link'] = f'=HYPERLINK("https://www.shodan.io/host/{host["ip"]}", "View Online")'
        hosts.append(host)

    dataframe = pd.DataFrame.from_records(hosts)
    dataframe.to_excel('output.xlsx', index=False)


if __name__ == '__main__':
    file = Path(sys.argv[1])
    if not file.exists():
        print(f'File {file} does not exist')
        sys.exit(0)

    parse_shodan_file(file)
