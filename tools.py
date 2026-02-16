import re
import httpx
import flag
import aiofiles
import socket
from ipwhois import IPWhois

from config import abuseipdb_api_key

class Tools:
    hosts = {
        'American Registry Internet Numbers': 'Cloudflare, Inc.',
        'Noah Kolossa': 'NeoProtect (Noah Kolossa)',
    }
    ovh = {
        'OVH SAS',
        'OVH Hosting, Inc.'
        'OVHCLOUD'
        'OVH Telecom (OVH SAS)'
    }
    def __init__(self):
        self.qfile = 'q.txt'
        pass

    async def isHost(self, text):
        isip = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$')
        isdomain = re.compile(
            r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d{1,5})?(\/.*)?$|^(?:[а-яА-ЯёЁ0-9-]+\.)+[а-яА-ЯёЁ]{2,}(:\d{1,5})?(\/.*)?$')
        isurl = re.compile(r'^(https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?)$')
        return bool(isip.match(text) or isdomain.match(text) or isurl.match(text))


    async def getnetname(self, ip):
        obj = IPWhois(ip)
        return obj.lookup_rdap()['network']['name']
    async def extractdomain(self, text):
        domain = re.sub(r'^https?://', '', text).split('/')[0]
        if re.search(r'[а-яА-Я]', domain):
            return domain.encode('idna').decode()
        return domain
    async def getminecraftinfo(self, host):
        async with httpx.AsyncClient() as client:
            response = await client.get('https://api.mcsrvstat.us/3/ ' + host)
            data = response.json()
            print(data)
            return data
    def gethostname(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return []
    async def whois(self, host):
        try:
            async with httpx.AsyncClient() as client:
                hostdec = await self.extractdomain(host)
                if not host.startswith(('http://', 'https://', 'http', 'https')):
                    hostdec = host.split(':')[0]
                    if ":" in host:
                        port = host.split(':')[1]
                    else:
                        port = 25565
                    minecraftdata = await self.getminecraftinfo(host)
                    response = await client.get(f'http://ip-api.com/json/{hostdec}?fields=query,country,city,isp,as,proxy,countryCode,hosting')
                    data = await self.msg(host, response.json(), True, minecraftdata, hostdec, port=port)
                else:
                    response = await client.get(f'http://ip-api.com/json/{hostdec}?fields=query,country,city,isp,as,proxy,countryCode,hosting')
                    data = await self.msg(host, response.json(), None, None, hostdec)
                    print(host)
                    count = await self.readquery()
                    await self.writequery(count + 1)
                return data
        except Exception as e:
            print(e)
            return []

    async def getabuses(self, host):
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': abuseipdb_api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': host,
            'maxAgeInDays': 30
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
            if response.status_code != 200:
                return 'UNKNOWN'
            data = response.json()
            reports = data.get('data', {}).get('totalReports', 'UNKNOWN')
            if reports == 0:
                reports = 'None'
            return reports

    async def msg(self, host, data, isMinecraft, minecraftdata, cleanhost, port=None):
        try:
            country = data['countryCode']
            flage = flag.flag(country)
            if data['isp'] in self.hosts:
                data['isp'] = self.hosts[data['isp']]
            elif data['isp'] in self.ovh:
                getnetname = await self.getnetname(data['query']) ## ovh RESOLVER !!! BREAKING.
                if 'vps' in getnetname.lower():
                    data['netname'] = '[OVH] VPS server, default protection.'
                elif 'game' in getnetname.lower():
                    data['netname'] = '[OVH] Server has GAME protection! Game OVH server.'
                elif getnetname.startswith('SD') and 'game' not in getnetname.lower() and 'vps' not in getnetname.lower():
                    data['netname'] = '[OVH] Dedicated server, has more resources than usual.'
                elif 'dedicated' in getnetname.lower() and 'game' not in getnetname.lower() and 'vps' not in getnetname.lower() and 'SD' not in getnetname.lower():
                    data['netname'] = '[OVH] Dedicated server, has more resources than usual.'
                elif getnetname.lower().startswith('ovh'):
                    data['netname'] = '[OVH] This is additional IP or OVH infrastructure!'


            elif data['isp'] == 'Hetzner Online GmbH': ## hetzner check
                getnetname = await self.getnetname(data['query'])
                print(getnetname.lower())
                if 'cloud' in getnetname.lower():
                    data['netname'] = '[Hetzner] VPS server, default protection.'

            proxy = "Yes" if data.get('proxy', False) else "No"
            hosting = "Yes" if data.get('hosting', False) else "No"
            netname_info = f"\n{data['netname']}" if data.get('netname') else ""
            abuses = await self.getabuses(data['query'])
            if isMinecraft and minecraftdata['online'] == True:
                isOnline = "Online" if minecraftdata.get('online', False) else "Offline"
                motd = minecraftdata['motd']['clean']
                version = minecraftdata['version']
                players = f"{minecraftdata['players']['online']}/{minecraftdata['players']['max']}"
                return f"🔎 {host}\n\n{data['query']}\n{flage} {data['country']}, {data['city']}\nℹ️ {data['isp']}\n {data['as']}{netname_info}\n🔕 AbuseIPDB: {abuses}\nProxy: {proxy}\nHosting: {hosting}\n\n🎮 Minecraft:\nStatus: {isOnline}\nMOTD: {motd}\nVersion: {version}\nPlayers: {players}"
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                hostname = self.gethostname(cleanhost)
                return f"🔎 {host}\n\n{data['query']}\n🌐 {hostname}\n{flage} {data['country']}, {data['city']}\nℹ️ {data['isp']}\n {data['as']}\n🔕 AbuseIPDB: {abuses}{netname_info}\nProxy: {proxy}\nHosting: {hosting}" ## IP
            return f"🔎 {host}\n\n{data['query']}\n{flage} {data['country']}, {data['city']}\nℹ️ {data['isp']}\n {data['as']}{netname_info}\nProxy: {proxy}\nHosting: {hosting}"  ## DOMAIN/URL
        except Exception as e:
            print(e)
            return 'Something wrong, maybe wrong host.'

    async def readquery(self):
        try:
            async with aiofiles.open(self.qfile, 'r') as file:
                content = await file.read()
                return int(content.strip()) if content.strip().isdigit() else 1
        except Exception as e:
            print(f"err: {e}")
            return 1

    async def writequery(self, count):
        async with aiofiles.open(self.qfile, 'w') as file:
            await file.write(str(count))