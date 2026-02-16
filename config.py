import configparser

config = configparser.ConfigParser()

config.read('config.ini')
token=config['bot'].get('token')
abuseipdb_api_key=config['settings'].get('abuseipdb_api_key')