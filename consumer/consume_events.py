#!/usr/bin/env python
import pika
import MySQLdb as mdb
from pika.credentials import ExternalCredentials
from configparser import SafeConfigParser
import os.path
import json


class ConsumeEvent:
    
    def __init__(self, config):
    
        conf_parse = SafeConfigParser()
        conf_parse.read(config)
    
        self.proxy = conf_parse.get('rmqproxy', 'proxy')
        self.proxy_port = int(conf_parse.get('rmqproxy', 'proxy_port'))
        self.proxy_vhost = conf_parse.get('rmqproxy', 'proxy_vhost')
        self.skey = conf_parse.get('rmqproxy', 'sensor_key')
       
        self.db_host = conf_parse.get('database', 'db_host')
        self.db_user = conf_parse.get('database', 'db_user')
        self.db_pass = conf_parse.get('database', 'db_pass')
        self.db_name = conf_parse.get('database', 'db_name')
        
        self.ssl_options = (
            {"ca_certs": conf_parse.get('rmqproxy', 'ca_cert'), 
            "certfile": conf_parse.get('rmqproxy', 'cert'),
            "keyfile": conf_parse.get('rmqproxy', 'key')})
            
    def build_channel(self):
        
        connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            self.proxy, self.proxy_port, self.proxy_vhost, 
            credentials=ExternalCredentials(), ssl=True, 
            ssl_options=self.ssl_options))
    
        channel = connection.channel()
        channel.queue_declare(queue=self.skey, durable=True)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(self.call_back, queue=self.skey)
        channel.start_consuming()
    
    def call_back(self, ch, method, properties, body):
        
        ch.basic_ack(delivery_tag = method.delivery_tag)
        str_obj = body.decode('utf-8')
        dict_event = json.loads(str_obj)
        if 'OSSEC' not in dict_event['signature']:
            self.insert_event(dict_event)
            #print(dict_event)
    
    def insert_event(self, event_row):
        
        db = mdb.connect(
            self.db_host, self.db_user,
            self.db_pass, self.db_name)
        
        with db:
            
            cur = db.cursor()
            sql_query = """
            INSERT INTO netevent (icmp_code, priority, src_port,
            sid, cid, timestamp, signature, class, src_ip,
            unified_event_id, sensor_key, dst_port, ip_ver,
            ip_proto, unified_event_ref, signature_id, icmp_type,
            dst_ip) VALUES (%(icmp_code)s,%(priority)s,%(src_port)s,
            %(sid)s,%(cid)s,%(timestamp)s,%(signature)s,%(class)s,
            %(src_ip)s,%(unified_event_id)s,%(sensor_key)s,%(dst_port)s,
            %(ip_ver)s,%(ip_proto)s,%(unified_event_ref)s,
            %(signature_id)s,%(icmp_type)s,%(dst_ip)s);
            """
            cur.execute(sql_query, event_row) 
                
def main():
    
    conf = SafeConfigParser()
    conf_file = 'consumer.yml'
    
    if os.path.exists(conf_file):
        conf.read(conf_file)
    else:
        print('Error: ' + conf_file + ' does not exist!')
        exit(1)
        
    my_event = ConsumeEvent(conf_file)
    my_event.build_channel()

if __name__ == '__main__':
    main()
