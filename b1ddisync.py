#!/usr/bin/python3
"""
BloxOne DDI Sync
The idea behind this tools is to get zonetransfer from two NameServers, compare it based on record types and make changes in the BloxOneDDI to synchronize it. 
Feel free to contribute! I'm not a developer.

This tool is experimental.

Special thanks to John Neerdael and Chris Marrison for their contribution to the community =) 

Stefan Braitti 
"""
import sys
import dns.resolver
import dns.reversename
import dns.zone
import dns.exception
import bloxone, argparse, logging, json

def getzone(ns, zone):
    records = []
    z = dns.zone.from_xfr(dns.query.xfr(ns, zone))

    for item in z.iterate_rdatas():
        record = {"name": item[0].to_text(), "ttl": item[1], "type": item[2].rdtype, "rdata": item[2].to_text().replace('"','')}
        records.append(record)
    return records

def main():
    # Parse CLI e set Options globally
    global options
    options = cliparser()

    # Creating and Configuring Logger
    if options.debug:
        debuglevel = logging.DEBUG
    else:
        debuglevel = logging.INFO
    Log_Format = "%(levelname)s %(asctime)s - %(message)s"

    logging.basicConfig(filename = options.logfile,
                        filemode = "a",
                        format = Log_Format, 
                        level = debuglevel)
    global logger 
    logger = logging.getLogger()

    # B1DDI Connection
    global b1ddi
    b1ddi = bloxone.b1ddi(options.config)

    # Define Tags
    if options.tags:
        tags = '"tags":' + options.tags
    else:
        tags = '"tags": {"importtype":"compare-tool"}'
    global jsonTags
    jsonTags = json.loads(json.dumps(tags)) 

    # Print welcome banner
    show("Starting Script...")
    show("Zone to sync: " +options.zone)
    show("Origin NS: "+options.server1)
    show("Bloxone NS: "+options.server2)
    list1, list2 = getzones()
    checksvc(list1, list2)
    show("Done!")

# Function to sync A Records
def sync_arecord(source, dest):
    show("Syncing A Records")
    # Get View ID
    view = b1ddi.get_id('/dns/view', key="name",value=options.viewname, include_path=True)

    # Get zone ID
    filter = ( '(fqdn=="'+options.zone+'.")and(view=="' + view + '")' )
    zone  = b1ddi.get('/dns/auth_zone', _filter=filter, _fields="fqdn,id")
    if zone.status_code in b1ddi.return_codes_ok:
        zoneid = zone.json()['results'][0]['id']
    else:
        show("Error found")
        logger.error("Zone " + options.zone + " not found")
        exit()

    # Remove different records from source
    for record in dest:
        if record not in source and record['type'] == 1:
            # Get Record ID
            response = b1ddi.get('/dns/record', _filter="(name_in_zone=='" + record['name'] + "') and (zone=='"+zoneid+"') and (dns_rdata=='" + record['rdata'] + "')")
            if response.status_code in b1ddi.return_codes_ok and len(response.json()['results']):
                recordid = response.json()['results'][0]['id'].split('/')[2]
                show("Removing A record " + record['name'] + " from B1DDI - RecordID:" + recordid)
                response = b1ddi.delete('/dns/record', id=recordid)
                if response.status_code in b1ddi.return_codes_ok:
                    show("Success!")
                else:  
                    show("Failed!")
                    logger.error("Error removing record: " + record['name'])
            else:
                show("Error found")
                logger.error("Record not found!")
    # Add records that are present in source
    for record in source:
        if record not in dest and record['type'] == 1:
            fqdn = record['name'] + '.' + options.zone
            address = record['rdata']
            comment = ''
            # Copy TTL
            if not options.ignorettl:
                jsonTTL = '"inheritance_sources":{"ttl":{"action":"override"}}, "ttl": ' + str(record['ttl']) + ','
            else:
                jsonTTL = ''

            body = ('{"view":"' + view + '","absolute_name_spec":"' + fqdn + '","rdata":{"address":"' + address + '"},"comment":"' + comment + '","type":"A", ' + jsonTTL + jsonTags + '}')  # Create body for network creation
            jsonBody = json.loads(
                json.dumps(body))  # Convert body to correct JSON and ensure quotes " are not escaped (ex. \")
            show("Creating A record on B1DDI: " + fqdn)
            response = b1ddi.create('/dns/record', body=jsonBody)  # Creating record
            if response.status_code in b1ddi.return_codes_ok:
                show("Success!")
            else:
                show("Error, please check the logs!")
                logger.error(jsonBody)
                logger.error(str(response.status_code) + " " + response.text)
                if options.stoponerror:
                    exit("ERROR FOUND, QUITING!")

#Function to sync AAAA records
def sync_aaaarecord(source, dest):
    show("Syncing AAAA Records")
    # Get View ID
    view = b1ddi.get_id('/dns/view', key="name",value=options.viewname, include_path=True)

    # Get zone ID
    filter = ( '(fqdn=="'+options.zone+'.")and(view=="' + view + '")' )
    zone  = b1ddi.get('/dns/auth_zone', _filter=filter, _fields="fqdn,id")
    if zone.status_code in b1ddi.return_codes_ok:
        zoneid = zone.json()['results'][0]['id']
    else:
        show("Error found")
        logger.error("Zone " + options.zone + " not found")
        exit()

    # Remove different records from source
    for record in dest:
        if record not in source and record['type'] == 28:
            # Get Record ID
            response = b1ddi.get('/dns/record', _filter="(name_in_zone=='" + record['name'] + "') and (zone=='"+zoneid+"') and (dns_rdata=='" + record['rdata'] + "')")
            if response.status_code in b1ddi.return_codes_ok and len(response.json()['results']):
                recordid = response.json()['results'][0]['id'].split('/')[2]
                show("Removing AAAA record " + record['name'] + " from B1DDI - RecordID:" + recordid)
                response = b1ddi.delete('/dns/record', id=recordid)
                if response.status_code in b1ddi.return_codes_ok:
                    show("Success!")
                else:  
                    show("Failed!")
                    logger.error("Error removing record: " + record['name'])
            else:
                show("Error found")
                logger.error("Record not found!")
    # Add records that are present in source
    for record in source:
        if record not in dest and record['type'] == 28:
            fqdn = record['name'] + '.' + options.zone
            address = record['rdata']
            comment = ''
            # Copy TTL
            if not options.ignorettl:
                jsonTTL = '"inheritance_sources":{"ttl":{"action":"override"}}, "ttl": ' + str(record['ttl']) + ','
            else:
                jsonTTL = ''

            body = ('{"view":"' + view + '","absolute_name_spec":"' + fqdn + '","rdata":{"address":"' + address + '"},"comment":"' + comment + '","type":"AAAA", ' + jsonTTL + jsonTags + '}')  # Create body for network creation
            jsonBody = json.loads(
                json.dumps(body))  # Convert body to correct JSON and ensure quotes " are not escaped (ex. \")
            show("Creating AAAA record on B1DDI: " + fqdn)
            response = b1ddi.create('/dns/record', body=jsonBody)  # Creating record
            if response.status_code in b1ddi.return_codes_ok:
                show("Success!")
            else:
                show("Error, please check the logs!")
                logger.error(jsonBody)
                logger.error(str(response.status_code) + " " + response.text)
                if options.stoponerror:
                    exit("ERROR FOUND, QUITING!")

#Function to sync CNAME records
def sync_cnamerecord(source, dest):
    show("Syncing CNAME Records")
    # Get View ID
    view = b1ddi.get_id('/dns/view', key="name",value=options.viewname, include_path=True)

    # Get zone ID
    filter = ( '(fqdn=="'+options.zone+'.")and(view=="' + view + '")' )
    zone  = b1ddi.get('/dns/auth_zone', _filter=filter, _fields="fqdn,id")
    if zone.status_code in b1ddi.return_codes_ok:
        zoneid = zone.json()['results'][0]['id']
    else:
        show("Error found")
        logger.error("Zone " + options.zone + " not found")
        exit()

    # Remove different records from source
    for record in dest:
        if record not in source and record['type'] == 5:
            show("Removing CNAME record " + record['name'] + " from B1DDI")
            # Fix records which are not ending in dot
            if not record['rdata'].endswith('.'):
                record['rdata'] = record['rdata']+'.'+options.zone+'.'
            # Get Record ID
            response = b1ddi.get('/dns/record', _filter="(name_in_zone=='" + record['name'] + "') and (zone=='"+zoneid+"') and (dns_rdata=='" + record['rdata'] + "')")
            if response.status_code in b1ddi.return_codes_ok and len(response.json()['results']):
                recordid = response.json()['results'][0]['id'].split('/')[2]
                response = b1ddi.delete('/dns/record', id=recordid)
                if response.status_code in b1ddi.return_codes_ok:
                    show("Success!")
                else:  
                    show("Failed!")
                    logger.error("Error removing CNAME record: " + record['name'])
            else:
                show("Error found")
                logger.error(response.text)
    # Add records that are present in source
    for record in source:
        if record not in dest and record['type'] == 5:
            fqdn = record['name'] + '.' + options.zone
            address = record['rdata']
            comment = ''
            # Copy TTL
            if not options.ignorettl:
                jsonTTL = '"inheritance_sources":{"ttl":{"action":"override"}}, "ttl": ' + str(record['ttl']) + ','
            else:
                jsonTTL = ''

            body = ('{"view":"' + view + '","absolute_name_spec":"' + fqdn + '","rdata":{"cname":"' + address + '"},"comment":"' + comment + '","type":"CNAME", ' + jsonTTL + jsonTags + '}')  # Create body for network creation
            jsonBody = json.loads(
                json.dumps(body))  # Convert body to correct JSON and ensure quotes " are not escaped (ex. \")
            show("Creating CNAME record on B1DDI: " + fqdn)
            response = b1ddi.create('/dns/record', body=jsonBody)  # Creating record
            if response.status_code in b1ddi.return_codes_ok:
                show("Success!")
            else:
                show("Error, please check the logs!")
                logger.error(jsonBody)
                logger.error(str(response.status_code) + " " + response.text)
                if options.stoponerror:
                    exit("ERROR FOUND, QUITING!")

#Function to sync MX records
def sync_mxrecord(source, dest):
    show("Syncing MX Records")
    # Get View ID
    view = b1ddi.get_id('/dns/view', key="name",value=options.viewname, include_path=True)

    # Get zone ID
    filter = ( '(fqdn=="'+options.zone+'.")and(view=="' + view + '")' )
    zone  = b1ddi.get('/dns/auth_zone', _filter=filter, _fields="fqdn,id")
    if zone.status_code in b1ddi.return_codes_ok:
        zoneid = zone.json()['results'][0]['id']
    else:
        show("Zone not found")
        logger.error("Zone " + options.zone + " not found")
        exit()

    # Remove different records from source
    for record in dest:
        if record not in source and record['type'] == 15:
            show("Removing MX record " + record['name'] + " from B1DDI")
            # Fix records which are not ending in dot
            if not record['rdata'].endswith('.'):
                record['rdata'] = record['rdata']+'.'+options.zone+'.'
            # Get Record ID
            filter = "(name_in_zone=='" + record['name'] + "') and (zone=='"+zoneid+"') and (dns_rdata=='" + record['rdata'] + "')"
            response = b1ddi.get('/dns/record', _filter=filter)
            if response.status_code in b1ddi.return_codes_ok and len(response.json()['results']):
                recordid = response.json()['results'][0]['id'].split('/')[2]
                response = b1ddi.delete('/dns/record', id=recordid)
                if response.status_code in b1ddi.return_codes_ok:
                    show("Success!")
                else:  
                    show("Failed!")
                    logger.error("Error removing MX record: " + record['name'])
            else:
                show("Record not found")
                logger.error(response.status_code)
                logger.error(response.text)
    # Add records that are present in source
    for record in source:
        if record not in dest and record['type'] == 15:
            fqdn = record['name'] + '.' + options.zone
            preference = record['rdata'].split(' ')[0]
            exchange = record['rdata'].split(' ')[1]
            comment = ''
            # Copy TTL
            if not options.ignorettl:
                jsonTTL = '"inheritance_sources":{"ttl":{"action":"override"}}, "ttl": ' + str(record['ttl']) + ','
            else:
                jsonTTL = ''

            body = ('{"view":"' + view + '","absolute_name_spec":"' + fqdn + '","rdata":{"exchange":"' + exchange + '","preference":' + preference + '},"comment":"' + comment + '","type":"MX", ' + jsonTTL + jsonTags + '}')  # Create body for network creation
            jsonBody = json.loads(
                json.dumps(body))  # Convert body to correct JSON and ensure quotes " are not escaped (ex. \")
            show("Creating MX record on B1DDI: " + fqdn)
            response = b1ddi.create('/dns/record', body=jsonBody)  # Creating record
            if response.status_code in b1ddi.return_codes_ok:
                show("Success!")
            else:
                show("Error, please check the logs!")
                logger.error(jsonBody)
                logger.error(str(response.status_code) + " " + response.text)
                if options.stoponerror:
                    exit("ERROR FOUND, QUITING!")

#Function to sync TXT records
def sync_txtrecord(source, dest):
    show("Syncing TXT Records")
    # Get View ID
    view = b1ddi.get_id('/dns/view', key="name",value=options.viewname, include_path=True)

    # Get zone ID
    filter = ( '(fqdn=="'+options.zone+'.")and(view=="' + view + '")' )
    zone  = b1ddi.get('/dns/auth_zone', _filter=filter, _fields="fqdn,id")
    if zone.status_code in b1ddi.return_codes_ok:
        zoneid = zone.json()['results'][0]['id']
    else:
        show("Error found")
        logger.error("Zone " + options.zone + " not found")
        exit()

    # Remove different records from source
    for record in dest:
        if record not in source and record['type'] == 16:
            # Get Record ID - Note: Escaped "
            response = b1ddi.get('/dns/record', _filter="(name_in_zone=='" + record['name'] + "')  and (zone=='"+zoneid+"') and (dns_rdata=='\"" + record['rdata'].replace(' ', '\" \"') + "\"')")
            if response.status_code in b1ddi.return_codes_ok and len(response.json()['results']):
                recordid = response.json()['results'][0]['id'].split('/')[2]
                show("Removing TXT record " + record['name'] + " from B1DDI - RecordID: " + recordid)
                response = b1ddi.delete('/dns/record', id=recordid)
                if response.status_code in b1ddi.return_codes_ok:
                    show("Success!")
                else:  
                    show("Failed!")
                    logger.error("Error removing TXT record: " + record['name'])
            else:
                show("Error found")
                logger.error("Record not found!")
    # Add records that are present in source
    for record in source:
        if record not in dest and record['type'] == 16:
            fqdn = record['name'] + '.' + options.zone
            text = record['rdata']
            comment = ''
            # Copy TTL
            if not options.ignorettl:
                jsonTTL = '"inheritance_sources":{"ttl":{"action":"override"}}, "ttl": ' + str(record['ttl']) + ','
            else:
                jsonTTL = ''

            body = ('{"view":"' + view + '","absolute_name_spec":"' + fqdn + '","rdata":{"text": "' + text + '"},"comment":"' + comment + '","type":"TXT", ' + jsonTTL + jsonTags + '}')  # Create body for network creation
            jsonBody = json.loads(
                json.dumps(body))  # Convert body to correct JSON and ensure quotes " are not escaped (ex. \")
            show("Creating TXT record on B1DDI: " + fqdn)
            response = b1ddi.create('/dns/record', body=jsonBody)  # Creating record
            if response.status_code in b1ddi.return_codes_ok:
                show("Success!")
            else:
                show("Error, please check the logs!")
                logger.error(jsonBody)
                logger.error(str(response.status_code) + " " + response.text)
                if options.stoponerror:
                    exit("ERROR FOUND, QUITING!")


    
def checksvc(list1, list2):
    if options.arecord:
        sync_arecord(list1, list2)
    if options.aaaarecord:
        sync_aaaarecord(list1, list2)
    if options.cnamerecord:
        sync_cnamerecord(list1, list2)
    if options.txtrecord:
        sync_txtrecord(list1, list2)
    if options.mxrecord:
        sync_mxrecord(list1, list2)


def getzones():
    list1 = getzone(options.server1, options.zone)
    list2 = getzone(options.server2, options.zone)
    
    return list1, list2


def cliparser():
    parser = argparse.ArgumentParser(description='This is a simple Zone comparison tool')
    parser.add_argument('-z', action="store", dest="zone", help="Zone to compare", required=True)
    parser.add_argument('--source', action="store", dest="server1", help="Source NameServer", required=True)
    parser.add_argument('--dest', action="store", dest="server2", help="Destination NameServer", required=True)
    parser.add_argument('-a', '--arecord', action="store_true", dest="arecord", help="Sync A record data")
    parser.add_argument('-t', '--txtrecord', action="store_true", dest="txtrecord", help="Sync TXT record data")
    parser.add_argument('-m', '--mxrecord', action="store_true", dest="mxrecord", help="Parse MX record data")
    parser.add_argument('--aaaa', action="store_true", dest="aaaarecord", help="Sync AAAA record data")
    parser.add_argument('--cname', action="store_true", dest="cnamerecord", help="Sync CNAME record data")
    parser.add_argument('--tags', action="store", dest="tags", help="Tags to apply to imported objects")
    parser.add_argument('--view', action="store", dest="viewname", help="View name", required=True)
    parser.add_argument('--debug', action="store_true", dest="debug", help="Log debug")
    parser.add_argument('--ignore-ttl', action="store_true", dest="ignorettl", help="Ignore TTL")
    parser.add_argument('--stop-on-error', action="store_true", dest="stoponerror", help="Quit script on error")
    parser.add_argument('-c', '--config', action="store", dest="config", help="Path to ini file with API key", required=True)
    parser.add_argument('--logfile', action="store", dest="logfile", help="Log file name (Default: logfile.log)", default="logfile.log")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')
    args = parser.parse_args()
    return args

def show(msg):
    print("[INFO] "+msg)
    logger.info(msg)

if __name__ == '__main__':
    main()
