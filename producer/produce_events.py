#!/usr/bin/python
import MySQLdb as mdb
from configparser import SafeConfigParser
import pika
from pika.credentials import ExternalCredentials
import os.path
import json

def query(time_type, time_number):
    
    db_query = """
    SELECT timestamp, class, priority,
    sid, cid, signature_id, signature, src_ip, dst_ip,
    src_port, dst_port, ip_proto, ip_ver, icmp_type,
    icmp_code, unified_event_id, unified_event_ref 
    FROM event WHERE timestamp BETWEEN
    DATE_SUB(NOW(), INTERVAL {} {}) AND NOW() 
    ORDER by timestamp
    """.format(time_type, time_number)
        
    return db_query

def main():
    
    conf = SafeConfigParser()
    conf_file = 'producer.conf'
    
    if os.path.exists(conf_file):
        conf.read(conf_file)
        for session in conf.sections():
            if session == 'main':
                time_number = conf.get(session, 'number')
                time_type = conf.get(session, 'timetype')
            elif session == 'rmqproxy':
                proxy = conf.get(session, 'proxy')
                proxy_port = int(conf.get(session, 'proxy_port'))
                proxy_vhost = conf.get(session, 'proxy_vhost')
                ca_cert = conf.get(session, 'ca_cert')
                cert = conf.get(session, 'cert')
                key = conf.get(session, 'key')
                skey = conf.get(session, 'sensor_key')
            else:
                db_host = conf.get(session, 'db_host')
                db_user = conf.get(session, 'db_user')
                db_pass = conf.get(session, 'db_pass')
                db_name = conf.get(session, 'db_name')
    else:
        print('Error: ' + conf_file + ' does not exist!')
        exit(1)
    
    ssl_options = (
        {"ca_certs": ca_cert, 
        "certfile": cert,
        "keyfile": key})
    
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            proxy, proxy_port, proxy_vhost, 
            credentials=ExternalCredentials(), ssl=True, 
            ssl_options=ssl_options))
    
    channel = connection.channel()
    channel.queue_declare(queue=skey, durable=True)
    
    db_query = query(time_number, time_type)
    db = mdb.connect(db_host, db_user, db_pass, db_name)
    
    with db:
        cursor = db.cursor(mdb.cursors.DictCursor)
        cursor.execute(db_query)
        rows = cursor.fetchall()
        
    for row in rows:
        # add sensor key 
        row.update({'sensor_key' : skey})
        # change datetime to string for serialize
        row.update({'timestamp' : str(row.get('timestamp'))})
        
        channel.basic_publish(
            exchange='', routing_key=skey,
            body=json.dumps(row), properties=pika.BasicProperties(
            delivery_mode = 2)) # make message persistent
    
    connection.close()

if __name__ == '__main__':
    main()

